package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/opensearch-project/opensearch-go/v4"
	"github.com/opensearch-project/opensearch-go/v4/opensearchapi"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("elasticsearch", &esBackend{})
}

// esBackend implements logsift.Backend for Elasticsearch and OpenSearch log queries.
type esBackend struct{}

// esInstance holds the resolved credentials for a single ES/OS instance.
// Note: CloudID from ElasticsearchInstanceConfig is not mapped here because
// opensearch-go does not support Elastic Cloud ID resolution. Users needing
// Elastic Cloud should provide the cluster address directly.
type esInstance struct {
	name      string
	addresses []string
	username  string
	password  string
	apiKey    string
	caCert    string
}

// Available returns true when at least one instance has addresses or a cloud ID configured.
func (b *esBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if len(creds.ElasticsearchAddresses) > 0 || creds.ElasticsearchCloudID != "" {
		return true
	}
	for _, inst := range creds.ElasticsearchInstances {
		if len(inst.Addresses) > 0 || inst.CloudID != "" {
			return true
		}
	}
	return false
}

// Search queries logs from all configured ES/OS instances.
func (b *esBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("elasticsearch: no instances configured")
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
		return nil, fmt.Errorf("elasticsearch: all instances failed: %s", strings.Join(errs, "; "))
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available indices from all configured ES/OS instances.
func (b *esBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("elasticsearch: no instances configured")
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

		resp, err := client.Cat.Indices(ctx, &opensearchapi.CatIndicesReq{})
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: cat indices: %v", inst.name, err))
			continue
		}

		for _, idx := range resp.Indices {
			name := idx.Index
			// Skip system indices.
			if strings.HasPrefix(name, ".") {
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
		return nil, fmt.Errorf("elasticsearch: all instances failed: %s", strings.Join(errs, "; "))
	}

	return sources, nil
}

// resolveInstances builds the list of ES/OS instances from credentials.
func (b *esBackend) resolveInstances(creds *logsift.Credentials) []esInstance {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-instance list.
	if len(creds.ElasticsearchInstances) > 0 {
		var instances []esInstance
		for _, c := range creds.ElasticsearchInstances {
			if len(c.Addresses) == 0 && c.CloudID == "" {
				continue
			}
			name := c.Name
			if name == "" {
				name = "elasticsearch"
			}
			instances = append(instances, esInstance{
				name:      name,
				addresses: c.Addresses,
				username:  c.Username,
				password:  c.Password,
				apiKey:    c.APIKey,
				caCert:    c.CACert,
			})
		}
		if len(instances) > 0 {
			return instances
		}
	}

	// Fallback to flat fields.
	if len(creds.ElasticsearchAddresses) > 0 || creds.ElasticsearchCloudID != "" {
		return []esInstance{{
			name:      "default",
			addresses: creds.ElasticsearchAddresses,
			username:  creds.ElasticsearchUsername,
			password:  creds.ElasticsearchPassword,
			apiKey:    creds.ElasticsearchAPIKey,
		}}
	}

	return nil
}

// newClient creates an OpenSearch API client for the given instance.
func (b *esBackend) newClient(inst esInstance) (*opensearchapi.Client, error) {
	cfg := opensearch.Config{
		Addresses: inst.addresses,
	}
	if inst.username != "" {
		cfg.Username = inst.username
		cfg.Password = inst.password
	}
	if inst.caCert != "" {
		cfg.CACert = []byte(inst.caCert)
	}
	// API key auth via Authorization header.
	if inst.apiKey != "" {
		cfg.Header = http.Header{
			"Authorization": []string{"ApiKey " + inst.apiKey},
		}
	}
	return opensearchapi.NewClient(opensearchapi.Config{Client: cfg})
}

// searchInstance queries a single ES/OS instance and returns normalized log entries.
func (b *esBackend) searchInstance(ctx context.Context, inst esInstance, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	client, err := b.newClient(inst)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	queryDSL := buildQueryDSL(q, maxEntries)
	body, err := json.Marshal(queryDSL)
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}

	// Determine the index pattern from the source, or use a wildcard.
	indices := []string{"*"}
	if q.Source != "" {
		indices = []string{logsift.SanitizeSourceName(q.Source)}
	}

	resp, err := client.Search(ctx, &opensearchapi.SearchReq{
		Indices: indices,
		Body:    strings.NewReader(string(body)),
	})
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}

	var entries []logsift.LogEntry
	for _, hit := range resp.Hits.Hits {
		entry := normalizeHit(hit)

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

// normalizeHit converts an ES/OS search hit into a LogEntry.
func normalizeHit(hit opensearchapi.SearchHit) logsift.LogEntry {
	entry := logsift.LogEntry{
		Timestamp: time.Now(),
		Severity:  logsift.SeverityInfo,
	}

	var source map[string]any
	if err := json.Unmarshal(hit.Source, &source); err != nil {
		entry.Message = string(hit.Source)
		return entry
	}

	// Extract timestamp from @timestamp or timestamp field.
	for _, key := range []string{"@timestamp", "timestamp"} {
		if v, ok := source[key]; ok {
			if s, ok := v.(string); ok {
				if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
					entry.Timestamp = t
					break
				}
				if t, err := time.Parse("2006-01-02T15:04:05.000Z", s); err == nil {
					entry.Timestamp = t
					break
				}
			}
		}
	}

	// Extract severity from log.level or level field.
	for _, key := range []string{"log.level", "level", "severity", "log_level"} {
		if v := getNestedString(source, key); v != "" {
			entry.Severity = logsift.ParseSeverity(v)
			break
		}
	}

	// Extract message.
	for _, key := range []string{"message", "msg", "log"} {
		if v := getNestedString(source, key); v != "" {
			entry.Message = v
			break
		}
	}

	// If no message, marshal the whole source.
	if entry.Message == "" {
		if b, err := json.Marshal(source); err == nil {
			entry.Message = string(b)
		}
	}

	// Extract service.
	for _, key := range []string{"service.name", "service", "app"} {
		if v := getNestedString(source, key); v != "" {
			entry.Service = v
			break
		}
	}

	// Extract host.
	for _, key := range []string{"host.name", "host", "hostname"} {
		if v := getNestedString(source, key); v != "" {
			entry.Host = v
			break
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

// getNestedString extracts a string value from a map, supporting dotted key paths.
func getNestedString(m map[string]any, key string) string {
	// Try direct key first.
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}

	// Try dotted path (e.g., "log.level" → m["log"]["level"]).
	parts := strings.SplitN(key, ".", 2)
	if len(parts) == 2 {
		if nested, ok := m[parts[0]]; ok {
			if nm, ok := nested.(map[string]any); ok {
				return getNestedString(nm, parts[1])
			}
		}
	}

	return ""
}

// buildQueryDSL constructs an Elasticsearch/OpenSearch Query DSL from the structured Query.
func buildQueryDSL(q *logsift.Query, maxEntries int) map[string]any {
	// If raw query is set, parse it as JSON and pass through.
	if q.RawQuery != "" {
		var raw map[string]any
		if err := json.Unmarshal([]byte(q.RawQuery), &raw); err == nil {
			return raw
		}
		// If not valid JSON, treat as a query_string query.
		return map[string]any{
			"size": maxEntries,
			"sort": []map[string]string{{"@timestamp": "desc"}},
			"query": map[string]any{
				"query_string": map[string]any{
					"query": q.RawQuery,
				},
			},
		}
	}

	var filters []map[string]any

	// Time range filter.
	if !q.StartTime.IsZero() || !q.EndTime.IsZero() {
		timeRange := map[string]any{}
		if !q.StartTime.IsZero() {
			timeRange["gte"] = q.StartTime.Format(time.RFC3339)
		}
		if !q.EndTime.IsZero() {
			timeRange["lte"] = q.EndTime.Format(time.RFC3339)
		}
		filters = append(filters, map[string]any{
			"range": map[string]any{
				"@timestamp": timeRange,
			},
		})
	}

	// Map canonical field filters to ECS-native names.
	mapped := logsift.MapFieldFilters(q.FieldFilters, logsift.FieldMappingElasticsearch)
	for field, value := range mapped {
		// Skip level — handled via severity_min.
		if field == "log.level" || field == "level" || field == "severity" {
			continue
		}
		filters = append(filters, map[string]any{
			"term": map[string]any{
				field: value,
			},
		})
	}

	// Severity filter.
	if q.SeverityMin != "" {
		sevLevels := severityLevelsForES(q.SeverityMin)
		if len(sevLevels) > 0 {
			filters = append(filters, map[string]any{
				"terms": map[string]any{
					"log.level": sevLevels,
				},
			})
		}
	}

	query := map[string]any{}
	if q.TextFilter != "" || len(filters) > 0 {
		boolQuery := map[string]any{}
		if len(filters) > 0 {
			boolQuery["filter"] = filters
		}
		if q.TextFilter != "" {
			boolQuery["must"] = []map[string]any{
				{"match": map[string]any{
					"message": map[string]any{
						"query": q.TextFilter,
					},
				}},
			}
		}
		query["bool"] = boolQuery
	} else {
		query["match_all"] = map[string]any{}
	}

	return map[string]any{
		"size":  maxEntries,
		"sort":  []map[string]string{{"@timestamp": "desc"}},
		"query": query,
	}
}

// severityLevelsForES returns all severity level strings at or above the given minimum,
// using lowercase values common in ECS log.level fields.
func severityLevelsForES(minSeverity string) []string {
	allES := []struct {
		esLevel  string
		severity string
	}{
		{"critical", logsift.SeverityCritical},
		{"fatal", logsift.SeverityCritical},
		{"error", logsift.SeverityError},
		{"warn", logsift.SeverityWarn},
		{"warning", logsift.SeverityWarn},
		{"info", logsift.SeverityInfo},
		{"debug", logsift.SeverityDebug},
		{"trace", logsift.SeverityTrace},
	}
	minIdx := logsift.SeverityIndex(minSeverity)
	var result []string
	for _, es := range allES {
		if logsift.SeverityIndex(es.severity) >= minIdx {
			result = append(result, es.esLevel)
		}
	}
	return result
}
