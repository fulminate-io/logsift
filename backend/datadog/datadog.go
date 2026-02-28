package datadog

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("datadog", &datadogBackend{})
}

// datadogBackend implements logsift.Backend for Datadog log queries.
type datadogBackend struct{}

// datadogInstance holds the resolved credentials for a single Datadog instance.
type datadogInstance struct {
	name   string
	apiKey string
	appKey string
	site   string // e.g., "datadoghq.com", "datadoghq.eu"
}

// Available returns true when at least one Datadog instance has both API and App keys configured.
func (b *datadogBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.DatadogAPIKey != "" && creds.DatadogAppKey != "" {
		return true
	}
	for _, inst := range creds.DatadogInstances {
		if inst.APIKey != "" && inst.AppKey != "" {
			return true
		}
	}
	return false
}

// Search queries logs from all configured Datadog instances.
func (b *datadogBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("datadog: no instances with API key and App key configured")
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
		return nil, fmt.Errorf("datadog: all instances failed: %s", strings.Join(errs, "; "))
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available log indexes from all configured Datadog instances.
func (b *datadogBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("datadog: no instances with API key and App key configured")
	}

	var sources []logsift.SourceInfo
	var errs []string
	seen := make(map[string]bool)

	for _, inst := range instances {
		ddCtx := b.buildContext(ctx, inst)
		cfg := datadog.NewConfiguration()
		client := datadog.NewAPIClient(cfg)
		api := datadogV1.NewLogsIndexesApi(client)

		resp, _, err := api.ListLogIndexes(ddCtx)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: list indexes: %v", inst.name, err))
			continue
		}

		for _, idx := range resp.GetIndexes() {
			name := idx.GetName()
			if prefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true

			desc := name
			if len(instances) > 1 {
				desc = fmt.Sprintf("%s (instance: %s)", desc, inst.name)
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

	if len(sources) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("datadog: all instances failed: %s", strings.Join(errs, "; "))
	}

	return sources, nil
}

// resolveInstances builds the list of Datadog instances from credentials.
func (b *datadogBackend) resolveInstances(creds *logsift.Credentials) []datadogInstance {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-instance list.
	if len(creds.DatadogInstances) > 0 {
		var instances []datadogInstance
		for _, c := range creds.DatadogInstances {
			if c.APIKey == "" || c.AppKey == "" {
				continue
			}
			name := c.Name
			if name == "" {
				name = "datadog"
			}
			instances = append(instances, datadogInstance{
				name:   name,
				apiKey: c.APIKey,
				appKey: c.AppKey,
				site:   c.Site,
			})
		}
		if len(instances) > 0 {
			return instances
		}
	}

	// Fallback to flat fields.
	if creds.DatadogAPIKey != "" && creds.DatadogAppKey != "" {
		return []datadogInstance{{
			name:   "default",
			apiKey: creds.DatadogAPIKey,
			appKey: creds.DatadogAppKey,
			site:   creds.DatadogSite,
		}}
	}

	return nil
}

// buildContext creates a context with Datadog authentication and site configuration.
func (b *datadogBackend) buildContext(ctx context.Context, inst datadogInstance) context.Context {
	ctx = context.WithValue(ctx, datadog.ContextAPIKeys, map[string]datadog.APIKey{
		"apiKeyAuth": {Key: inst.apiKey},
		"appKeyAuth": {Key: inst.appKey},
	})
	if inst.site != "" {
		ctx = context.WithValue(ctx, datadog.ContextServerVariables, map[string]string{
			"site": inst.site,
		})
	}
	return ctx
}

// searchInstance queries a single Datadog instance and returns normalized log entries.
func (b *datadogBackend) searchInstance(ctx context.Context, inst datadogInstance, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	ddCtx := b.buildContext(ctx, inst)
	cfg := datadog.NewConfiguration()
	client := datadog.NewAPIClient(cfg)
	api := datadogV2.NewLogsApi(client)

	ddQuery := buildQuery(q)

	// Build time range strings.
	var from, to string
	if !q.StartTime.IsZero() {
		from = q.StartTime.Format("2006-01-02T15:04:05Z")
	}
	if !q.EndTime.IsZero() {
		to = q.EndTime.Format("2006-01-02T15:04:05Z")
	}

	// Use the source as the index if specified.
	var indexes []string
	if q.Source != "" {
		indexes = []string{logsift.SanitizeSourceName(q.Source)}
	}

	// Build the request body.
	filter := &datadogV2.LogsQueryFilter{
		Query: datadog.PtrString(ddQuery),
	}
	if from != "" {
		filter.From = datadog.PtrString(from)
	}
	if to != "" {
		filter.To = datadog.PtrString(to)
	}
	if len(indexes) > 0 {
		filter.Indexes = indexes
	}

	pageLimit := int32(maxEntries)
	if pageLimit > 1000 {
		pageLimit = 1000
	}

	body := datadogV2.LogsListRequest{
		Filter: filter,
		Sort:   datadogV2.LOGSSORT_TIMESTAMP_DESCENDING.Ptr(),
		Page: &datadogV2.LogsListRequestPage{
			Limit: datadog.PtrInt32(pageLimit),
		},
	}

	var allEntries []logsift.LogEntry
	var cursor *string

	for {
		if cursor != nil {
			body.Page = &datadogV2.LogsListRequestPage{
				Limit:  datadog.PtrInt32(pageLimit),
				Cursor: cursor,
			}
		}

		resp, _, err := api.ListLogs(ddCtx, *datadogV2.NewListLogsOptionalParameters().WithBody(body))
		if err != nil {
			return nil, fmt.Errorf("query: %w", err)
		}

		for _, log := range resp.GetData() {
			entry := normalizeEntry(log)

			// Client-side text filter.
			if q.TextFilter != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(q.TextFilter)) {
				continue
			}

			// Client-side severity filter.
			if q.SeverityMin != "" && !logsift.SeverityAtLeast(entry.Severity, q.SeverityMin) {
				continue
			}

			allEntries = append(allEntries, entry)

			if len(allEntries) >= maxEntries {
				break
			}
		}

		if len(allEntries) >= maxEntries {
			break
		}

		// Check for next page cursor.
		meta := resp.GetMeta()
		page := meta.GetPage()
		after, ok := page.GetAfterOk()
		if !ok || after == nil || *after == "" {
			break
		}
		cursor = after
	}

	// Sort by timestamp desc.
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.After(allEntries[j].Timestamp)
	})

	return allEntries, nil
}

// normalizeEntry converts a Datadog log into a LogEntry.
func normalizeEntry(log datadogV2.Log) logsift.LogEntry {
	attrs := log.GetAttributes()
	entry := logsift.LogEntry{
		Timestamp: attrs.GetTimestamp(),
		Message:   attrs.GetMessage(),
		Service:   attrs.GetService(),
		Host:      attrs.GetHost(),
		Severity:  logsift.ParseSeverity(attrs.GetStatus()),
	}

	// If severity is default INFO, try embedded detection from the message.
	if entry.Severity == logsift.SeverityInfo && attrs.GetStatus() == "" {
		if embedded := logsift.DetectEmbeddedSeverity(entry.Message); embedded != "" {
			entry.Severity = embedded
		}
	}

	return entry
}

// buildQuery constructs a Datadog log search query from the structured Query.
func buildQuery(q *logsift.Query) string {
	// If raw query is set, use it directly.
	if q.RawQuery != "" {
		return q.RawQuery
	}

	var parts []string

	// Map canonical field filters to Datadog-native field names.
	mapped := logsift.MapFieldFilters(q.FieldFilters, logsift.FieldMappingDatadog)

	for field, value := range mapped {
		// Skip level — handled via severity_min.
		if field == "status" || field == "level" || field == "severity" {
			continue
		}

		// Datadog reserved fields (service, host, source) don't use @ prefix.
		// Kubernetes tags are searched via tag syntax.
		switch field {
		case "service", "host", "source":
			parts = append(parts, fmt.Sprintf("%s:%s", field, escapeValue(value)))
		case "kube_namespace", "kube_pod_name", "kube_container_name", "kube_deployment", "kube_cluster_name":
			parts = append(parts, fmt.Sprintf("%s:%s", field, escapeValue(value)))
		default:
			// Custom attributes use @ prefix.
			parts = append(parts, fmt.Sprintf("@%s:%s", field, escapeValue(value)))
		}
	}

	// Add severity filter.
	if q.SeverityMin != "" {
		sevLevels := severityLevelsForDD(q.SeverityMin)
		if len(sevLevels) > 0 {
			var statusParts []string
			for _, s := range sevLevels {
				statusParts = append(statusParts, fmt.Sprintf("status:%s", s))
			}
			parts = append(parts, fmt.Sprintf("(%s)", strings.Join(statusParts, " OR ")))
		}
	}

	// Add text filter as free-text search.
	if q.TextFilter != "" {
		parts = append(parts, fmt.Sprintf("%q", q.TextFilter))
	}

	if len(parts) == 0 {
		return "*"
	}
	return strings.Join(parts, " ")
}

// severityLevelsForDD returns the Datadog status values at or above the given severity.
func severityLevelsForDD(minSeverity string) []string {
	// Datadog uses: emergency, alert, critical, error, warn, info, debug, trace
	allDD := []struct {
		ddStatus string
		severity string
	}{
		{"emergency", logsift.SeverityCritical},
		{"alert", logsift.SeverityCritical},
		{"critical", logsift.SeverityCritical},
		{"error", logsift.SeverityError},
		{"warn", logsift.SeverityWarn},
		{"info", logsift.SeverityInfo},
		{"debug", logsift.SeverityDebug},
		{"trace", logsift.SeverityTrace},
	}
	minIdx := logsift.SeverityIndex(minSeverity)
	var result []string
	for _, dd := range allDD {
		if logsift.SeverityIndex(dd.severity) >= minIdx {
			result = append(result, dd.ddStatus)
		}
	}
	return result
}

// escapeValue escapes special characters in a Datadog query value.
func escapeValue(s string) string {
	// Wrap in quotes if the value contains spaces or special characters.
	if strings.ContainsAny(s, " \t\"\\()[]{}:") {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return fmt.Sprintf(`"%s"`, s)
	}
	return s
}
