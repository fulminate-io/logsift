package azuremonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/azquery"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("azuremonitor", &azureBackend{})
}

// azureBackend implements logsift.Backend for Azure Monitor Log Analytics.
type azureBackend struct{}

// azureInstance holds the resolved credentials for a single Azure Monitor workspace.
type azureInstance struct {
	name         string
	tenantID     string
	clientID     string
	clientSecret string
	workspaceID  string
}

// Available returns true when at least one workspace has a workspace ID configured.
func (b *azureBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.AzureWorkspaceID != "" {
		return true
	}
	for _, inst := range creds.AzureInstances {
		if inst.WorkspaceID != "" {
			return true
		}
	}
	return false
}

// Search queries logs from all configured Azure Monitor workspaces.
func (b *azureBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("azuremonitor: no workspaces configured")
	}

	maxPerInstance := q.MaxRawEntries
	if maxPerInstance <= 0 {
		maxPerInstance = 500
	}
	if len(instances) > 1 {
		maxPerInstance = maxPerInstance / len(instances)
		maxPerInstance = max(maxPerInstance, 50)
	}

	var allEntries []logsift.LogEntry
	var errs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, inst := range instances {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries, err := b.searchInstance(ctx, inst, q, maxPerInstance)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", inst.name, err))
				return
			}
			allEntries = append(allEntries, entries...)
		}()
	}
	wg.Wait()

	// Apply max entries cap after parallel collection.
	if q.MaxRawEntries > 0 && len(allEntries) > q.MaxRawEntries {
		allEntries = allEntries[:q.MaxRawEntries]
	}

	if len(allEntries) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("azuremonitor: all instances failed: %s", strings.Join(errs, "; "))
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available tables from Azure Monitor Log Analytics workspaces.
func (b *azureBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("azuremonitor: no workspaces configured")
	}

	var sources []logsift.SourceInfo
	var errs []string
	seen := make(map[string]bool)

	for _, inst := range instances {
		client, err := b.newClient(inst)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", inst.name, err))
			continue
		}

		// Use KQL to discover tables with recent data.
		kql := `search * | where TimeGenerated > ago(30d) | distinct $table`
		res, err := client.QueryWorkspace(ctx, inst.workspaceID, azquery.Body{
			Query: to.Ptr(kql),
		}, nil)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: list tables: %v", inst.name, err))
			continue
		}

		if len(res.Tables) > 0 {
			for _, row := range res.Tables[0].Rows {
				if len(row) == 0 {
					continue
				}
				name, ok := row[0].(string)
				if !ok || name == "" {
					continue
				}
				if prefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
					continue
				}
				if seen[name] {
					continue
				}
				seen[name] = true

				desc := name
				if len(instances) > 1 {
					desc = fmt.Sprintf("%s (workspace: %s)", desc, inst.name)
				}
				sources = append(sources, logsift.SourceInfo{
					Name:        name,
					Description: desc,
				})

				if len(sources) >= 100 {
					return sources, nil
				}
			}
		}
	}

	if len(sources) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("azuremonitor: all instances failed: %s", strings.Join(errs, "; "))
	}

	return sources, nil
}

// resolveInstances builds the list of Azure Monitor workspaces from credentials.
func (b *azureBackend) resolveInstances(creds *logsift.Credentials) []azureInstance {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-instance list.
	if len(creds.AzureInstances) > 0 {
		var instances []azureInstance
		for _, c := range creds.AzureInstances {
			if c.WorkspaceID == "" {
				continue
			}
			name := c.Name
			if name == "" {
				name = "azuremonitor"
			}
			instances = append(instances, azureInstance{
				name:         name,
				tenantID:     c.TenantID,
				clientID:     c.ClientID,
				clientSecret: c.ClientSecret,
				workspaceID:  c.WorkspaceID,
			})
		}
		if len(instances) > 0 {
			return instances
		}
	}

	// Fallback to flat fields.
	if creds.AzureWorkspaceID != "" {
		return []azureInstance{{
			name:         "default",
			tenantID:     creds.AzureTenantID,
			clientID:     creds.AzureClientID,
			clientSecret: creds.AzureClientSecret,
			workspaceID:  creds.AzureWorkspaceID,
		}}
	}

	return nil
}

// newClient creates an Azure Monitor Logs client for the given instance.
func (b *azureBackend) newClient(inst azureInstance) (*azquery.LogsClient, error) {
	if inst.tenantID != "" && inst.clientID != "" && inst.clientSecret != "" {
		cred, err := azidentity.NewClientSecretCredential(inst.tenantID, inst.clientID, inst.clientSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("create credential: %w", err)
		}
		return azquery.NewLogsClient(cred, nil)
	}

	// Fall back to DefaultAzureCredential (managed identity, env vars, CLI).
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create default credential: %w", err)
	}
	return azquery.NewLogsClient(cred, nil)
}

// searchInstance queries a single Azure Monitor workspace and returns normalized log entries.
func (b *azureBackend) searchInstance(ctx context.Context, inst azureInstance, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	client, err := b.newClient(inst)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	kql := buildKQL(q, maxEntries)

	body := azquery.Body{
		Query: to.Ptr(kql),
	}

	// Add timespan if start/end times are set.
	if !q.StartTime.IsZero() && !q.EndTime.IsZero() {
		ts := azquery.NewTimeInterval(q.StartTime, q.EndTime)
		body.Timespan = to.Ptr(ts)
	} else if !q.StartTime.IsZero() {
		ts := azquery.NewTimeInterval(q.StartTime, time.Now().UTC())
		body.Timespan = to.Ptr(ts)
	} else if !q.EndTime.IsZero() {
		// Only EndTime set — query from 24 hours before EndTime.
		ts := azquery.NewTimeInterval(q.EndTime.Add(-24*time.Hour), q.EndTime)
		body.Timespan = to.Ptr(ts)
	}

	res, err := client.QueryWorkspace(ctx, inst.workspaceID, body, &azquery.LogsClientQueryWorkspaceOptions{
		Options: &azquery.LogsQueryOptions{
			Wait: to.Ptr(60),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	if len(res.Tables) == 0 {
		return nil, nil
	}

	table := res.Tables[0]

	// Build column name index.
	colIndex := make(map[string]int, len(table.Columns))
	for i, col := range table.Columns {
		if col.Name != nil {
			colIndex[*col.Name] = i
		}
	}

	var entries []logsift.LogEntry
	for _, row := range table.Rows {
		entry := normalizeRow(row, colIndex)

		// Client-side text filter.
		if q.TextFilter != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(q.TextFilter)) {
			continue
		}

		// Client-side severity filter.
		if q.SeverityMin != "" && !logsift.SeverityAtLeast(entry.Severity, q.SeverityMin) {
			continue
		}

		entries = append(entries, entry)
		if len(entries) >= maxEntries {
			break
		}
	}

	// Sort by timestamp desc.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, nil
}

// normalizeRow converts an Azure Monitor table row into a LogEntry.
func normalizeRow(row azquery.Row, colIndex map[string]int) logsift.LogEntry {
	entry := logsift.LogEntry{
		Timestamp: time.Now(),
		Severity:  logsift.SeverityInfo,
	}

	// Extract timestamp.
	if idx, ok := colIndex["TimeGenerated"]; ok && idx < len(row) {
		if s, ok := row[idx].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
				entry.Timestamp = t
			} else if t, err := time.Parse("2006-01-02T15:04:05Z", s); err == nil {
				entry.Timestamp = t
			}
		}
	}

	// Extract severity from LogLevel.
	if idx, ok := colIndex["LogLevel"]; ok && idx < len(row) {
		if s, ok := row[idx].(string); ok && s != "" {
			entry.Severity = logsift.ParseSeverity(s)
		}
	}

	// Extract message from LogMessage (dynamic field - can be string or map).
	if idx, ok := colIndex["LogMessage"]; ok && idx < len(row) {
		switch v := row[idx].(type) {
		case string:
			entry.Message = v
		case map[string]any:
			if msg := logsift.ExtractMessageFromMap(v); msg != "" {
				entry.Message = msg
			} else if b, err := json.Marshal(v); err == nil {
				entry.Message = string(b)
			}
		}
	}

	// Fallback to message field.
	if entry.Message == "" {
		if idx, ok := colIndex["message"]; ok && idx < len(row) {
			if s, ok := row[idx].(string); ok {
				entry.Message = s
			}
		}
	}

	// Extract host from Computer.
	if idx, ok := colIndex["Computer"]; ok && idx < len(row) {
		if s, ok := row[idx].(string); ok {
			entry.Host = s
		}
	}

	// Fall back to embedded severity detection.
	if entry.Severity == logsift.SeverityInfo {
		if embedded := logsift.DetectEmbeddedSeverity(entry.Message); embedded != "" {
			entry.Severity = embedded
		}
	}

	return entry
}

// buildKQL constructs a KQL query from the structured Query.
func buildKQL(q *logsift.Query, maxEntries int) string {
	// If raw query is set, use it directly.
	if q.RawQuery != "" {
		return q.RawQuery
	}

	var sb strings.Builder

	// Table source — default to ContainerLogV2 if not specified.
	source := q.Source
	if source == "" {
		source = "ContainerLogV2"
	}
	sb.WriteString(logsift.SanitizeSourceName(source))

	// Map canonical field filters to Azure Monitor-native names.
	mapped := logsift.MapFieldFilters(q.FieldFilters, logsift.FieldMappingAzureMonitor)

	for field, value := range mapped {
		// Skip level — handled via severity_min.
		if field == "LogLevel" || field == "level" || field == "severity" {
			continue
		}
		sb.WriteString(fmt.Sprintf("\n| where %s == %q", field, value))
	}

	// Add severity filter.
	if q.SeverityMin != "" {
		sevLevels := severityLevelsForKQL(q.SeverityMin)
		if len(sevLevels) > 0 {
			quoted := make([]string, len(sevLevels))
			for i, s := range sevLevels {
				quoted[i] = fmt.Sprintf("%q", s)
			}
			sb.WriteString(fmt.Sprintf("\n| where LogLevel in (%s)", strings.Join(quoted, ", ")))
		}
	}

	// Add text filter.
	if q.TextFilter != "" {
		sb.WriteString(fmt.Sprintf("\n| where tostring(LogMessage) contains %q", q.TextFilter))
	}

	// Sort and limit.
	sb.WriteString("\n| order by TimeGenerated desc")
	sb.WriteString(fmt.Sprintf("\n| take %d", maxEntries))

	return sb.String()
}

// severityLevelsForKQL returns the ContainerLogV2 LogLevel values at or above the given minimum.
func severityLevelsForKQL(minSeverity string) []string {
	// ContainerLogV2 LogLevel values are uppercase.
	allKQL := []struct {
		kqlLevel string
		severity string
	}{
		{"CRITICAL", logsift.SeverityCritical},
		{"ERROR", logsift.SeverityError},
		{"WARNING", logsift.SeverityWarn},
		{"INFO", logsift.SeverityInfo},
		{"DEBUG", logsift.SeverityDebug},
		{"TRACE", logsift.SeverityTrace},
	}
	minIdx := logsift.SeverityIndex(minSeverity)
	var result []string
	for _, kql := range allKQL {
		if logsift.SeverityIndex(kql.severity) >= minIdx {
			result = append(result, kql.kqlLevel)
		}
	}
	return result
}
