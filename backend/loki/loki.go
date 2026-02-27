package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("loki", &lokiBackend{})
}

// lokiBackend implements logsift.Backend for Loki log queries.
type lokiBackend struct{}

// lokiInstance holds the resolved credentials for a single Loki instance.
type lokiInstance struct {
	name        string
	address     string
	tenantID    string
	username    string
	password    string
	bearerToken string
}

// Available returns true when at least one Loki instance has an address configured.
func (b *lokiBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.LokiAddress != "" {
		return true
	}
	for _, inst := range creds.LokiInstances {
		if inst.Address != "" {
			return true
		}
	}
	return false
}

// Search queries logs from all configured Loki instances.
func (b *lokiBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("loki: no instances with address configured")
	}

	maxPerInstance := q.MaxRawEntries
	if maxPerInstance <= 0 {
		maxPerInstance = 500
	}
	if len(instances) > 1 {
		maxPerInstance = maxPerInstance / len(instances)
		maxPerInstance = max(maxPerInstance, 50)
	}
	// Loki's default max_entries_limit_per_query is 5000.
	if maxPerInstance > 5000 {
		maxPerInstance = 5000
	}

	var allEntries []logsift.LogEntry
	var errs []string

	for _, inst := range instances {
		entries, err := b.searchInstance(ctx, inst, q, maxPerInstance)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", inst.name, err))
			continue
		}
		allEntries = append(allEntries, entries...)

		if len(allEntries) >= q.MaxRawEntries {
			allEntries = allEntries[:q.MaxRawEntries]
			break
		}
	}

	// If all instances failed, return the errors instead of empty results.
	if len(allEntries) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("loki: all instances failed: %s", strings.Join(errs, "; "))
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available namespaces from Loki label values.
func (b *lokiBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("loki: no instances with address configured")
	}

	var sources []logsift.SourceInfo
	var errs []string
	seen := make(map[string]bool)

	for _, inst := range instances {
		values, err := b.listLabelValues(ctx, inst, "namespace")
		if err != nil || len(values) == 0 {
			// Fallback: try job label values if namespace doesn't exist.
			values, err = b.listLabelValues(ctx, inst, "job")
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", inst.name, err))
				continue
			}
		}

		for _, val := range values {
			if prefix != "" && !strings.HasPrefix(strings.ToLower(val), strings.ToLower(prefix)) {
				continue
			}
			if seen[val] {
				continue
			}
			seen[val] = true

			desc := val
			if len(instances) > 1 {
				desc = fmt.Sprintf("%s (instance: %s)", val, inst.name)
			}
			sources = append(sources, logsift.SourceInfo{
				Name:        val,
				Description: desc,
			})

			if len(sources) >= 100 {
				return sources, nil
			}
		}
	}

	if len(sources) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("loki: all instances failed: %s", strings.Join(errs, "; "))
	}

	return sources, nil
}

// resolveInstances builds the list of Loki instances from credentials.
func (b *lokiBackend) resolveInstances(creds *logsift.Credentials) []lokiInstance {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-instance list.
	if len(creds.LokiInstances) > 0 {
		var instances []lokiInstance
		for _, c := range creds.LokiInstances {
			if c.Address == "" {
				continue
			}
			instances = append(instances, lokiInstance{
				name:        c.Name,
				address:     strings.TrimRight(c.Address, "/"),
				tenantID:    c.TenantID,
				username:    c.Username,
				password:    c.Password,
				bearerToken: c.BearerToken,
			})
		}
		if len(instances) > 0 {
			return instances
		}
	}

	// Fallback to flat fields.
	if creds.LokiAddress != "" {
		return []lokiInstance{{
			name:     "default",
			address:  strings.TrimRight(creds.LokiAddress, "/"),
			tenantID: creds.LokiTenantID,
			username: creds.LokiUsername,
			password: creds.LokiPassword,
		}}
	}

	return nil
}

// searchInstance queries a single Loki instance and returns normalized log entries.
func (b *lokiBackend) searchInstance(ctx context.Context, inst lokiInstance, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	logQL := buildLogQL(q)

	params := url.Values{
		"query":     {logQL},
		"limit":     {strconv.Itoa(maxEntries)},
		"direction": {"backward"},
	}

	if !q.StartTime.IsZero() {
		params.Set("start", strconv.FormatInt(q.StartTime.UnixNano(), 10))
	}
	if !q.EndTime.IsZero() {
		params.Set("end", strconv.FormatInt(q.EndTime.UnixNano(), 10))
	}

	body, err := doRequest(ctx, inst, http.MethodGet, "/loki/api/v1/query_range", params)
	if err != nil {
		return nil, fmt.Errorf("loki: query_range for %s: %w", inst.name, err)
	}

	var resp lokiQueryResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("loki: parse response from %s: %w", inst.name, err)
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("loki: query failed on %s: status=%s", inst.name, resp.Status)
	}

	var entries []logsift.LogEntry
	for _, stream := range resp.Data.Result {
		for _, val := range stream.Values {
			if len(val) < 2 {
				continue
			}

			entry := normalizeEntry(stream.Stream, val[0], val[1])

			// Client-side text filter.
			if q.TextFilter != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(q.TextFilter)) {
				continue
			}

			// Client-side severity filter.
			if q.SeverityMin != "" && !logsift.SeverityAtLeast(entry.Severity, q.SeverityMin) {
				continue
			}

			entries = append(entries, entry)
		}
	}

	// Sort by timestamp desc.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}

	return entries, nil
}

// normalizeEntry converts a Loki stream entry into a LogEntry.
func normalizeEntry(stream map[string]string, tsStr, line string) logsift.LogEntry {
	entry := logsift.LogEntry{
		Timestamp: time.Now(),
		Severity:  logsift.SeverityInfo,
	}

	// Parse nanosecond timestamp.
	if ns, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
		entry.Timestamp = time.Unix(0, ns)
	}

	// Extract service from stream labels (priority order).
	entry.Service = extractStreamLabel(stream, "container", "app_kubernetes_io_name", "service_name", "job")

	// Extract host from stream labels.
	entry.Host = extractStreamLabel(stream, "node", "pod", "instance")

	// Parse the log line for message and severity.
	entry.Message, entry.Severity = parseLogLine(line)

	return entry
}

// extractStreamLabel returns the first non-empty value from the stream labels.
// For the "job" label, splits on "/" and takes the last segment.
func extractStreamLabel(stream map[string]string, keys ...string) string {
	for _, key := range keys {
		if v, ok := stream[key]; ok && v != "" {
			if key == "job" {
				// job labels are often "namespace/service" — take the last part.
				if idx := strings.LastIndex(v, "/"); idx >= 0 {
					return v[idx+1:]
				}
			}
			return v
		}
	}
	return ""
}

// parseLogLine extracts message and severity from a raw log line.
// Loki provides timestamps separately, so no timestamp stripping is needed.
func parseLogLine(line string) (message, severity string) {
	message = line
	severity = logsift.SeverityInfo

	// Some Loki lines have a severity prefix like "INFO  [logger.name] {json...}"
	// Try to detect and strip it.
	trimmed := line
	if idx := strings.IndexByte(trimmed, ' '); idx > 0 && idx <= 8 {
		prefix := strings.TrimSpace(trimmed[:idx])
		if sev := logsift.ParseSeverity(prefix); sev != logsift.SeverityInfo || strings.EqualFold(prefix, "INFO") {
			// Only strip if prefix is a recognized severity (not default INFO for unknown).
			rest := strings.TrimSpace(trimmed[idx+1:])
			if len(rest) > 0 && rest[0] == '[' {
				// Strip "[logger.name] " prefix too.
				if end := strings.IndexByte(rest, ']'); end >= 0 {
					rest = strings.TrimSpace(rest[end+1:])
				}
			}
			if len(rest) > 0 && rest[0] == '{' {
				// The remainder is JSON — parse it with the extracted severity.
				severity = sev
				trimmed = rest
			}
		}
	}

	// Try JSON parsing for structured logs.
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var m map[string]any
		if err := json.Unmarshal([]byte(trimmed), &m); err == nil {
			if msg := logsift.ExtractMessageFromMap(m); msg != trimmed {
				message = msg
			}
			// Extract severity from JSON fields.
			for _, key := range []string{"level", "severity", "lvl"} {
				if v, ok := m[key]; ok {
					if s, ok := v.(string); ok && s != "" {
						severity = logsift.ParseSeverity(s)
						return
					}
				}
			}
			// If we already extracted severity from prefix, keep it.
			if severity != logsift.SeverityInfo {
				return
			}
		}
	}

	// Fall back to embedded severity detection for plain text.
	if embedded := logsift.DetectEmbeddedSeverity(message); embedded != "" {
		severity = embedded
	}

	return
}

// buildLogQL constructs a LogQL query from the structured Query.
func buildLogQL(q *logsift.Query) string {
	// Map canonical field filters to Loki labels.
	mapped := logsift.MapFieldFilters(q.FieldFilters, logsift.FieldMappingLoki)

	// Build stream selector from mapped fields.
	var matchers []string

	// Source field maps to namespace (matching K8s backend pattern).
	if q.Source != "" {
		matchers = append(matchers, fmt.Sprintf(`namespace=%q`, q.Source))
	}

	for label, value := range mapped {
		// Skip level — we do client-side severity filtering.
		if label == "level" {
			continue
		}
		matchers = append(matchers, fmt.Sprintf(`%s=%q`, label, value))
	}

	// Loki requires at least one matcher in the stream selector.
	var selector string
	if len(matchers) > 0 {
		// Sort for deterministic output.
		sort.Strings(matchers)
		selector = "{" + strings.Join(matchers, ", ") + "}"
	} else {
		selector = `{namespace=~".+"}`
	}

	var query strings.Builder
	query.WriteString(selector)

	// Append line filter for text search.
	if q.TextFilter != "" {
		query.WriteString(fmt.Sprintf(` |= %q`, q.TextFilter))
	}

	// Append raw query as-is (passthrough LogQL).
	if q.RawQuery != "" {
		query.WriteString(" ")
		query.WriteString(q.RawQuery)
	}

	return query.String()
}

// listLabelValues queries Loki for values of a specific label.
func (b *lokiBackend) listLabelValues(ctx context.Context, inst lokiInstance, label string) ([]string, error) {
	params := url.Values{}
	// Scope to last 24h for relevance.
	now := time.Now()
	params.Set("start", strconv.FormatInt(now.Add(-24*time.Hour).UnixNano(), 10))
	params.Set("end", strconv.FormatInt(now.UnixNano(), 10))

	body, err := doRequest(ctx, inst, http.MethodGet, "/loki/api/v1/label/"+url.PathEscape(label)+"/values", params)
	if err != nil {
		return nil, err
	}

	var resp lokiLabelResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("loki: parse label response: %w", err)
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("loki: label query failed: status=%s", resp.Status)
	}

	return resp.Data, nil
}

// doRequest executes an HTTP request against a Loki instance with auth headers.
func doRequest(ctx context.Context, inst lokiInstance, method, path string, params url.Values) ([]byte, error) {
	u := inst.address + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, fmt.Errorf("loki: build request: %w", err)
	}

	// Set auth headers.
	if inst.username != "" {
		req.SetBasicAuth(inst.username, inst.password)
	} else if inst.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+inst.bearerToken)
	}
	if inst.tenantID != "" {
		req.Header.Set("X-Scope-OrgID", inst.tenantID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki: request to %s: %w", inst.name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("loki: read response from %s: %w", inst.name, err)
	}

	if resp.StatusCode != http.StatusOK {
		// Truncate long error bodies.
		errBody := string(body)
		if len(errBody) > 200 {
			errBody = errBody[:200] + "..."
		}
		return nil, fmt.Errorf("loki: %s returned HTTP %d: %s", inst.name, resp.StatusCode, errBody)
	}

	return body, nil
}

// Loki API response types.

type lokiQueryResponse struct {
	Status string        `json:"status"`
	Data   lokiQueryData `json:"data"`
}

type lokiQueryData struct {
	ResultType string       `json:"resultType"`
	Result     []lokiStream `json:"result"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"` // Each value is [nanosecond_string, line]
}

type lokiLabelResponse struct {
	Status string   `json:"status"`
	Data   []string `json:"data"`
}
