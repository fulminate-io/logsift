package newrelic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	logsift "github.com/fulminate-io/logsift"
)

const (
	nerdGraphUS = "https://api.newrelic.com/graphql"
	nerdGraphEU = "https://api.eu.newrelic.com/graphql"
)

func init() {
	logsift.Register("newrelic", &nrBackend{})
}

// nrBackend implements logsift.Backend for New Relic via NerdGraph (GraphQL) + NRQL.
type nrBackend struct{}

// nrInstance holds the resolved credentials for a single New Relic account.
type nrInstance struct {
	name      string
	apiKey    string
	accountID int
	endpoint  string
}

// Available returns true when at least one instance has an API key and account ID configured.
func (b *nrBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.NewRelicAPIKey != "" && creds.NewRelicAccountID > 0 {
		return true
	}
	for _, inst := range creds.NewRelicInstances {
		if inst.APIKey != "" && inst.AccountID > 0 {
			return true
		}
	}
	return false
}

// Search queries logs from all configured New Relic accounts.
func (b *nrBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("newrelic: no instances configured")
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
		return nil, fmt.Errorf("newrelic: all instances failed: %s", strings.Join(errs, "; "))
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available log types from New Relic accounts.
func (b *nrBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("newrelic: no instances configured")
	}

	var sources []logsift.SourceInfo
	var errs []string
	seen := make(map[string]bool)

	for _, inst := range instances {
		// Discover log types via NRQL.
		nrql := "SELECT uniques(logtype) FROM Log SINCE 7 days ago LIMIT MAX"
		results, err := b.queryNRQL(ctx, inst, nrql)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: list sources: %v", inst.name, err))
			continue
		}

		for _, result := range results {
			// Result format: {"uniques.logtype": ["type1", "type2", ...]}
			for _, v := range result {
				items, ok := v.([]any)
				if !ok {
					continue
				}
				for _, item := range items {
					name, ok := item.(string)
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
						desc = fmt.Sprintf("%s (account: %s)", desc, inst.name)
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
	}

	if len(sources) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("newrelic: all instances failed: %s", strings.Join(errs, "; "))
	}

	return sources, nil
}

// resolveInstances builds the list of New Relic accounts from credentials.
func (b *nrBackend) resolveInstances(creds *logsift.Credentials) []nrInstance {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-instance list.
	if len(creds.NewRelicInstances) > 0 {
		var instances []nrInstance
		for _, c := range creds.NewRelicInstances {
			if c.APIKey == "" || c.AccountID <= 0 {
				continue
			}
			name := c.Name
			if name == "" {
				name = "newrelic"
			}
			instances = append(instances, nrInstance{
				name:      name,
				apiKey:    c.APIKey,
				accountID: c.AccountID,
				endpoint:  regionEndpoint(c.Region),
			})
		}
		if len(instances) > 0 {
			return instances
		}
	}

	// Fallback to flat fields.
	if creds.NewRelicAPIKey != "" && creds.NewRelicAccountID > 0 {
		return []nrInstance{{
			name:      "default",
			apiKey:    creds.NewRelicAPIKey,
			accountID: creds.NewRelicAccountID,
			endpoint:  regionEndpoint(creds.NewRelicRegion),
		}}
	}

	return nil
}

// regionEndpoint returns the NerdGraph endpoint for the given region.
func regionEndpoint(region string) string {
	if strings.EqualFold(region, "EU") {
		return nerdGraphEU
	}
	return nerdGraphUS
}

// searchInstance queries a single New Relic account and returns normalized log entries.
func (b *nrBackend) searchInstance(ctx context.Context, inst nrInstance, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	nrql := buildNRQL(q, maxEntries)

	results, err := b.queryNRQL(ctx, inst, nrql)
	if err != nil {
		return nil, err
	}

	var entries []logsift.LogEntry
	for _, result := range results {
		entry := normalizeResult(result)

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

// queryNRQL executes a NRQL query via NerdGraph and returns the results.
func (b *nrBackend) queryNRQL(ctx context.Context, inst nrInstance, nrql string) ([]map[string]any, error) {
	gqlQuery := `query($accountId: Int!, $nrqlQuery: Nrql!) {
  actor {
    account(id: $accountId) {
      nrql(query: $nrqlQuery, timeout: 30) {
        results
      }
    }
  }
}`

	reqBody := graphqlRequest{
		Query: gqlQuery,
		Variables: map[string]any{
			"accountId": inst.accountID,
			"nrqlQuery": nrql,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, inst.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", inst.apiKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query: HTTP %d: %s", resp.StatusCode, logsift.TruncateString(string(respBody), 500))
	}

	var gqlResp graphqlResponse
	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("graphql error: %s", gqlResp.Errors[0].Message)
	}

	// Extract results from nested response: data.actor.account.nrql.results
	return extractResults(gqlResp.Data)
}

// graphqlRequest is the request body for NerdGraph.
type graphqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

// graphqlResponse is the response body from NerdGraph.
type graphqlResponse struct {
	Data   map[string]any `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

// extractResults navigates the NerdGraph response to get results.
func extractResults(data map[string]any) ([]map[string]any, error) {
	actor, ok := data["actor"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing actor in response")
	}
	account, ok := actor["account"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing account in response")
	}
	nrql, ok := account["nrql"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing nrql in response")
	}
	rawResults, ok := nrql["results"].([]any)
	if !ok {
		// results field missing or unexpected type — query may have returned no data.
		if nrql["results"] == nil {
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected results type in response: %T", nrql["results"])
	}

	results := make([]map[string]any, 0, len(rawResults))
	for _, r := range rawResults {
		if m, ok := r.(map[string]any); ok {
			results = append(results, m)
		}
	}
	return results, nil
}

// normalizeResult converts a New Relic result map into a LogEntry.
func normalizeResult(result map[string]any) logsift.LogEntry {
	entry := logsift.LogEntry{
		Timestamp: time.Now(),
		Severity:  logsift.SeverityInfo,
	}

	// Extract timestamp — New Relic uses epoch milliseconds.
	if v, ok := result["timestamp"].(float64); ok && v > 0 {
		entry.Timestamp = time.UnixMilli(int64(v)).UTC()
	}

	// Extract message.
	if v, ok := result["message"].(string); ok && v != "" {
		entry.Message = v
	}

	// Extract severity from level or severity field.
	for _, key := range []string{"level", "severity"} {
		if v, ok := result[key].(string); ok && v != "" {
			entry.Severity = logsift.ParseSeverity(v)
			break
		}
	}

	// Extract host.
	for _, key := range []string{"hostname", "host"} {
		if v, ok := result[key].(string); ok && v != "" {
			entry.Host = v
			break
		}
	}

	// Extract service.
	for _, key := range []string{"service.name", "entity.name"} {
		if v, ok := result[key].(string); ok && v != "" {
			entry.Service = v
			break
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

// buildNRQL constructs a NRQL query from the structured Query.
func buildNRQL(q *logsift.Query, maxEntries int) string {
	// If raw query is set, use it directly.
	if q.RawQuery != "" {
		return q.RawQuery
	}

	var conditions []string

	// Map canonical field filters to New Relic-native names.
	mapped := logsift.MapFieldFilters(q.FieldFilters, logsift.FieldMappingNewRelic)
	for field, value := range mapped {
		// Skip level — handled via severity filter below.
		if field == "level" || field == "severity" {
			continue
		}
		// Backtick-quote dotted field names.
		if strings.Contains(field, ".") {
			conditions = append(conditions, fmt.Sprintf("`%s` = '%s'", field, escapeNRQL(value)))
		} else {
			conditions = append(conditions, fmt.Sprintf("%s = '%s'", field, escapeNRQL(value)))
		}
	}

	// Severity filter.
	if q.SeverityMin != "" {
		sevLevels := severityLevelsForNRQL(q.SeverityMin)
		if len(sevLevels) > 0 {
			quoted := make([]string, len(sevLevels))
			for i, s := range sevLevels {
				quoted[i] = fmt.Sprintf("'%s'", s)
			}
			conditions = append(conditions, fmt.Sprintf("level IN (%s)", strings.Join(quoted, ", ")))
		}
	}

	// Text filter.
	if q.TextFilter != "" {
		conditions = append(conditions, fmt.Sprintf("message LIKE '%%%s%%'", escapeNRQL(q.TextFilter)))
	}

	// Source filter (logtype).
	if q.Source != "" {
		conditions = append(conditions, fmt.Sprintf("logtype = '%s'", escapeNRQL(logsift.SanitizeSourceName(q.Source))))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Time range.
	timeClause := " SINCE 1 hour ago"
	if !q.StartTime.IsZero() {
		timeClause = fmt.Sprintf(" SINCE %d", q.StartTime.UnixMilli())
		if !q.EndTime.IsZero() {
			timeClause += fmt.Sprintf(" UNTIL %d", q.EndTime.UnixMilli())
		}
	}

	// Cap at NRQL max of 5000.
	limit := maxEntries
	if limit > 5000 {
		limit = 5000
	}

	return fmt.Sprintf("SELECT * FROM Log%s%s ORDER BY timestamp DESC LIMIT %d", whereClause, timeClause, limit)
}

// severityLevelsForNRQL returns severity level strings at or above the given minimum.
func severityLevelsForNRQL(minSeverity string) []string {
	allNRQL := []struct {
		nrLevel  string
		severity string
	}{
		{"CRITICAL", logsift.SeverityCritical},
		{"FATAL", logsift.SeverityCritical},
		{"ERROR", logsift.SeverityError},
		{"WARN", logsift.SeverityWarn},
		{"WARNING", logsift.SeverityWarn},
		{"INFO", logsift.SeverityInfo},
		{"DEBUG", logsift.SeverityDebug},
		{"TRACE", logsift.SeverityTrace},
	}
	minIdx := logsift.SeverityIndex(minSeverity)
	var result []string
	for _, nr := range allNRQL {
		if logsift.SeverityIndex(nr.severity) >= minIdx {
			result = append(result, nr.nrLevel)
		}
	}
	return result
}

// escapeNRQL escapes single quotes in NRQL string values.
func escapeNRQL(s string) string {
	return strings.ReplaceAll(s, "'", "\\'")
}

