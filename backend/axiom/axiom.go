package axiom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/axiomhq/axiom-go/axiom"
	"github.com/axiomhq/axiom-go/axiom/query"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("axiom", &axiomBackend{})
}

// axiomBackend implements logsift.Backend for Axiom log queries.
type axiomBackend struct{}

// axiomInstance holds the resolved credentials for a single Axiom instance.
type axiomInstance struct {
	name  string
	token string
	orgID string
	url   string
}

// Available returns true when at least one Axiom instance has a token configured.
func (b *axiomBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.AxiomToken != "" {
		return true
	}
	for _, inst := range creds.AxiomInstances {
		if inst.Token != "" {
			return true
		}
	}
	return false
}

// Search queries logs from all configured Axiom instances.
func (b *axiomBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("axiom: no instances with token configured")
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
		return nil, fmt.Errorf("axiom: all instances failed: %s", strings.Join(errs, "; "))
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available datasets from all configured Axiom instances.
func (b *axiomBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("axiom: no instances with token configured")
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

		datasets, err := client.Datasets.List(ctx)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: list datasets: %v", inst.name, err))
			continue
		}

		for _, ds := range datasets {
			if prefix != "" && !strings.HasPrefix(strings.ToLower(ds.Name), strings.ToLower(prefix)) {
				continue
			}
			if seen[ds.Name] {
				continue
			}
			seen[ds.Name] = true

			desc := ds.Description
			if desc == "" {
				desc = ds.Name
			}
			if len(instances) > 1 {
				desc = fmt.Sprintf("%s (instance: %s)", desc, inst.name)
			}
			sources = append(sources, logsift.SourceInfo{
				Name:        ds.Name,
				Description: desc,
			})

			if len(sources) >= 100 {
				return sources, nil
			}
		}
	}

	if len(sources) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("axiom: all instances failed: %s", strings.Join(errs, "; "))
	}

	return sources, nil
}

// resolveInstances builds the list of Axiom instances from credentials.
func (b *axiomBackend) resolveInstances(creds *logsift.Credentials) []axiomInstance {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-instance list.
	if len(creds.AxiomInstances) > 0 {
		var instances []axiomInstance
		for _, c := range creds.AxiomInstances {
			if c.Token == "" {
				continue
			}
			name := c.Name
			if name == "" {
				name = "axiom"
			}
			instances = append(instances, axiomInstance{
				name:  name,
				token: c.Token,
				orgID: c.OrgID,
				url:   c.URL,
			})
		}
		if len(instances) > 0 {
			return instances
		}
	}

	// Fallback to flat fields.
	if creds.AxiomToken != "" {
		return []axiomInstance{{
			name:  "default",
			token: creds.AxiomToken,
			orgID: creds.AxiomOrgID,
			url:   creds.AxiomURL,
		}}
	}

	return nil
}

// newClient creates an Axiom client for the given instance.
func (b *axiomBackend) newClient(inst axiomInstance) (*axiom.Client, error) {
	opts := []axiom.Option{
		axiom.SetToken(inst.token),
		axiom.SetNoEnv(),
	}
	if inst.orgID != "" {
		opts = append(opts, axiom.SetOrganizationID(inst.orgID))
	}
	if inst.url != "" {
		opts = append(opts, axiom.SetURL(inst.url))
	}
	return axiom.NewClient(opts...)
}

// searchInstance queries a single Axiom instance and returns normalized log entries.
func (b *axiomBackend) searchInstance(ctx context.Context, inst axiomInstance, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	client, err := b.newClient(inst)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	apl := buildAPL(q, maxEntries)

	// Build query options for time range.
	var opts []query.Option
	if !q.StartTime.IsZero() {
		opts = append(opts, query.SetStartTime(q.StartTime))
	}
	if !q.EndTime.IsZero() {
		opts = append(opts, query.SetEndTime(q.EndTime))
	}

	res, err := client.Query(ctx, apl, opts...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	if len(res.Tables) == 0 {
		return nil, nil
	}

	table := res.Tables[0]

	// Build field name index from table fields.
	fieldIndex := make(map[string]int, len(table.Fields))
	for i, f := range table.Fields {
		fieldIndex[f.Name] = i
	}

	var entries []logsift.LogEntry
	for row := range table.Rows() {
		entry := normalizeEntry(row, fieldIndex)

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

// normalizeEntry converts an Axiom row into a LogEntry.
func normalizeEntry(row query.Row, fieldIndex map[string]int) logsift.LogEntry {
	entry := logsift.LogEntry{
		Timestamp: time.Now(),
		Severity:  logsift.SeverityInfo,
	}

	// Extract timestamp from _time field.
	if idx, ok := fieldIndex["_time"]; ok && idx < len(row) {
		switch v := row[idx].(type) {
		case string:
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				entry.Timestamp = t
			}
		case time.Time:
			entry.Timestamp = v
		}
	}

	// Extract severity from level or severity field.
	for _, key := range []string{"level", "severity", "log_level"} {
		if idx, ok := fieldIndex[key]; ok && idx < len(row) {
			if s, ok := row[idx].(string); ok && s != "" {
				entry.Severity = logsift.ParseSeverity(s)
				break
			}
		}
	}

	// Extract message.
	for _, key := range []string{"message", "msg", "_raw", "body", "log"} {
		if idx, ok := fieldIndex[key]; ok && idx < len(row) {
			switch v := row[idx].(type) {
			case string:
				if v != "" {
					entry.Message = v
					break
				}
			case map[string]any:
				if msg := logsift.ExtractMessageFromMap(v); msg != "" {
					entry.Message = msg
					break
				}
			}
			if entry.Message != "" {
				break
			}
		}
	}

	// If no message found, try to construct from all fields.
	if entry.Message == "" {
		m := make(map[string]any, len(fieldIndex))
		for name, idx := range fieldIndex {
			if idx < len(row) && row[idx] != nil {
				m[name] = row[idx]
			}
		}
		if b, err := json.Marshal(m); err == nil {
			entry.Message = string(b)
		}
	}

	// Extract service.
	for _, key := range []string{"service", "service.name", "app", "application"} {
		if idx, ok := fieldIndex[key]; ok && idx < len(row) {
			if s, ok := row[idx].(string); ok && s != "" {
				entry.Service = s
				break
			}
		}
	}

	// Extract host.
	for _, key := range []string{"host", "hostname", "node", "instance"} {
		if idx, ok := fieldIndex[key]; ok && idx < len(row) {
			if s, ok := row[idx].(string); ok && s != "" {
				entry.Host = s
				break
			}
		}
	}

	// Fall back to embedded severity detection if no level field found.
	if entry.Severity == logsift.SeverityInfo {
		if embedded := logsift.DetectEmbeddedSeverity(entry.Message); embedded != "" {
			entry.Severity = embedded
		}
	}

	return entry
}

// buildAPL constructs an APL query from the structured Query.
func buildAPL(q *logsift.Query, maxEntries int) string {
	// If raw query is set, use it directly.
	if q.RawQuery != "" {
		return q.RawQuery
	}

	var sb strings.Builder

	// Dataset source — default to wildcard if not specified.
	source := q.Source
	if source == "" {
		source = "*"
	}
	sb.WriteString(fmt.Sprintf("['%s']", logsift.SanitizeSourceName(source)))

	// Map canonical field filters to Axiom-native field names.
	mapped := logsift.MapFieldFilters(q.FieldFilters, logsift.FieldMappingAxiom)

	// Add field filters as where clauses.
	for field, value := range mapped {
		// Skip level — handled via severity_min.
		if field == "level" || field == "severity" {
			continue
		}
		sb.WriteString(fmt.Sprintf("\n| where ['%s'] == \"%s\"", field, escapeAPLString(value)))
	}

	// Add severity filter.
	if q.SeverityMin != "" {
		sevLevels := severityLevelsAtLeast(q.SeverityMin)
		if len(sevLevels) > 0 {
			quoted := make([]string, len(sevLevels))
			for i, s := range sevLevels {
				quoted[i] = fmt.Sprintf("\"%s\"", strings.ToLower(s))
			}
			sb.WriteString(fmt.Sprintf("\n| where ['level'] in (%s)", strings.Join(quoted, ", ")))
		}
	}

	// Add text filter.
	if q.TextFilter != "" {
		sb.WriteString(fmt.Sprintf("\n| where ['message'] contains \"%s\"", escapeAPLString(q.TextFilter)))
	}

	// Sort and limit.
	sb.WriteString("\n| order by _time desc")
	sb.WriteString(fmt.Sprintf("\n| take %d", maxEntries))

	return sb.String()
}

// severityLevelsAtLeast returns all severity levels at or above the given minimum.
func severityLevelsAtLeast(minSeverity string) []string {
	all := []string{
		logsift.SeverityCritical,
		logsift.SeverityError,
		logsift.SeverityWarn,
		logsift.SeverityInfo,
		logsift.SeverityDebug,
		logsift.SeverityTrace,
	}
	minIdx := logsift.SeverityIndex(minSeverity)
	var result []string
	for _, s := range all {
		if logsift.SeverityIndex(s) >= minIdx {
			result = append(result, s)
		}
	}
	return result
}

// escapeAPLString escapes special characters in APL string literals.
func escapeAPLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
