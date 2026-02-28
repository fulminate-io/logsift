package splunk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("splunk", &splunkBackend{})
}

// splunkBackend implements logsift.Backend for Splunk Enterprise/Cloud via REST API.
type splunkBackend struct{}

// splunkInstance holds the resolved credentials for a single Splunk instance.
type splunkInstance struct {
	name          string
	baseURL       string
	token         string
	username      string
	password      string
	tlsSkipVerify bool
}

// Available returns true when at least one instance has a URL configured.
func (b *splunkBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.SplunkURL != "" {
		return true
	}
	for _, inst := range creds.SplunkInstances {
		if inst.URL != "" {
			return true
		}
	}
	return false
}

// Search queries logs from all configured Splunk instances.
func (b *splunkBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("splunk: no instances configured")
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
		return nil, fmt.Errorf("splunk: all instances failed: %s", strings.Join(errs, "; "))
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available indexes from Splunk instances.
func (b *splunkBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("splunk: no instances configured")
	}

	var sources []logsift.SourceInfo
	var errs []string
	seen := make(map[string]bool)

	for _, inst := range instances {
		indexes, err := b.listIndexes(ctx, inst)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", inst.name, err))
			continue
		}

		for _, name := range indexes {
			// Skip internal indexes.
			if strings.HasPrefix(name, "_") {
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
		return nil, fmt.Errorf("splunk: all instances failed: %s", strings.Join(errs, "; "))
	}

	return sources, nil
}

// listIndexes fetches available index names from a single Splunk instance.
func (b *splunkBackend) listIndexes(ctx context.Context, inst splunkInstance) ([]string, error) {
	client := b.httpClient(inst)
	reqURL := fmt.Sprintf("%s/services/data/indexes?output_mode=json&count=-1", strings.TrimRight(inst.baseURL, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("list indexes: %w", err)
	}
	b.setAuth(req, inst)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list indexes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list indexes: HTTP %d: %s", resp.StatusCode, logsift.TruncateString(string(body), 200))
	}

	var result struct {
		Entry []struct {
			Name string `json:"name"`
		} `json:"entry"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode indexes: %w", err)
	}

	var names []string
	for _, entry := range result.Entry {
		names = append(names, entry.Name)
	}
	return names, nil
}

// resolveInstances builds the list of Splunk instances from credentials.
func (b *splunkBackend) resolveInstances(creds *logsift.Credentials) []splunkInstance {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-instance list.
	if len(creds.SplunkInstances) > 0 {
		var instances []splunkInstance
		for _, c := range creds.SplunkInstances {
			if c.URL == "" {
				continue
			}
			name := c.Name
			if name == "" {
				name = "splunk"
			}
			instances = append(instances, splunkInstance{
				name:          name,
				baseURL:       c.URL,
				token:         c.Token,
				username:      c.Username,
				password:      c.Password,
				tlsSkipVerify: c.TLSSkipVerify,
			})
		}
		if len(instances) > 0 {
			return instances
		}
	}

	// Fallback to flat fields.
	if creds.SplunkURL != "" {
		return []splunkInstance{{
			name:          "default",
			baseURL:       creds.SplunkURL,
			token:         creds.SplunkToken,
			username:      creds.SplunkUsername,
			password:      creds.SplunkPassword,
			tlsSkipVerify: creds.SplunkTLSSkipVerify,
		}}
	}

	return nil
}

// httpClient creates an HTTP client for the given instance.
func (b *splunkBackend) httpClient(inst splunkInstance) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if inst.tlsSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-configured dev option
	}
	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
}

// setAuth sets the authentication header on a request.
func (b *splunkBackend) setAuth(req *http.Request, inst splunkInstance) {
	if inst.token != "" {
		// Token can be either "Bearer <jwt>" or "Splunk <token>".
		if strings.HasPrefix(inst.token, "Bearer ") || strings.HasPrefix(inst.token, "Splunk ") {
			req.Header.Set("Authorization", inst.token)
		} else {
			req.Header.Set("Authorization", "Splunk "+inst.token)
		}
	} else if inst.username != "" && inst.password != "" {
		req.SetBasicAuth(inst.username, inst.password)
	}
}

// searchInstance queries a single Splunk instance using oneshot search.
func (b *splunkBackend) searchInstance(ctx context.Context, inst splunkInstance, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	client := b.httpClient(inst)

	spl := buildSPL(q, maxEntries)

	// Use oneshot export for streaming results.
	reqURL := fmt.Sprintf("%s/services/search/v2/jobs/export", strings.TrimRight(inst.baseURL, "/"))

	form := url.Values{}
	form.Set("search", spl)
	form.Set("output_mode", "json")
	form.Set("count", fmt.Sprintf("%d", maxEntries))

	// Add time range parameters using Unix epoch seconds (RFC3339 is not
	// reliably supported by the Splunk REST API).
	if !q.StartTime.IsZero() {
		form.Set("earliest_time", strconv.FormatInt(q.StartTime.Unix(), 10))
	}
	if !q.EndTime.IsZero() {
		form.Set("latest_time", strconv.FormatInt(q.EndTime.Unix(), 10))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b.setAuth(req, inst)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search: HTTP %d: %s", resp.StatusCode, logsift.TruncateString(string(body), 500))
	}

	// Splunk export returns newline-delimited JSON objects.
	var entries []logsift.LogEntry
	decoder := json.NewDecoder(resp.Body)
	for decoder.More() {
		var event exportEvent
		if err := decoder.Decode(&event); err != nil {
			// Skip malformed lines.
			continue
		}

		// Skip non-result messages (preview, metadata).
		if event.Preview {
			continue
		}
		if event.Result == nil {
			continue
		}

		entry := normalizeResult(event.Result)

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

// exportEvent represents a single event from Splunk's export endpoint.
type exportEvent struct {
	Preview bool               `json:"preview"`
	Result  map[string]any     `json:"result"`
}

// normalizeResult converts a Splunk result map into a LogEntry.
func normalizeResult(result map[string]any) logsift.LogEntry {
	entry := logsift.LogEntry{
		Timestamp: time.Now(),
		Severity:  logsift.SeverityInfo,
	}

	// Extract timestamp from _time.
	if v, ok := result["_time"].(string); ok && v != "" {
		// Splunk _time can be RFC3339 or custom format.
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.000-07:00",
			"2006-01-02T15:04:05.000+00:00",
		} {
			if t, err := time.Parse(layout, v); err == nil {
				entry.Timestamp = t
				break
			}
		}
	}

	// Extract message from _raw (full raw event text).
	if v, ok := result["_raw"].(string); ok && v != "" {
		entry.Message = v
	}

	// Extract severity from common level fields.
	for _, key := range []string{"level", "log_level", "severity", "loglevel"} {
		if v, ok := result[key].(string); ok && v != "" {
			entry.Severity = logsift.ParseSeverity(v)
			break
		}
	}

	// Extract host.
	if v, ok := result["host"].(string); ok && v != "" {
		entry.Host = v
	}

	// Extract service from sourcetype or service field.
	for _, key := range []string{"service", "sourcetype"} {
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

// buildSPL constructs an SPL query from the structured Query.
func buildSPL(q *logsift.Query, maxEntries int) string {
	// If raw query is set, use it directly.
	if q.RawQuery != "" {
		// Ensure it starts with "search" if it doesn't already.
		if !strings.HasPrefix(strings.TrimSpace(q.RawQuery), "search") && !strings.HasPrefix(q.RawQuery, "|") {
			return "search " + q.RawQuery
		}
		return q.RawQuery
	}

	var parts []string

	// Index source.
	if q.Source != "" {
		parts = append(parts, fmt.Sprintf("index=%s", logsift.SanitizeSourceName(q.Source)))
	} else {
		parts = append(parts, "index=*")
	}

	// Map canonical field filters to Splunk-native names.
	mapped := logsift.MapFieldFilters(q.FieldFilters, logsift.FieldMappingSplunk)
	for field, value := range mapped {
		// Skip level — handled via severity filter below.
		if field == "level" || field == "log_level" || field == "severity" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%q", field, value))
	}

	// Severity filter.
	if q.SeverityMin != "" {
		sevLevels := severityLevelsForSPL(q.SeverityMin)
		if len(sevLevels) > 0 {
			// Use OR across level fields and values.
			var levelTerms []string
			for _, sev := range sevLevels {
				levelTerms = append(levelTerms, fmt.Sprintf("level=%q", sev))
			}
			parts = append(parts, "("+strings.Join(levelTerms, " OR ")+")")
		}
	}

	// Text filter.
	if q.TextFilter != "" {
		parts = append(parts, fmt.Sprintf("%q", q.TextFilter))
	}

	spl := "search " + strings.Join(parts, " ")

	// Add sort and limit via SPL pipes.
	spl += fmt.Sprintf(" | sort -_time | head %d", maxEntries)

	return spl
}

// severityLevelsForSPL returns severity level strings at or above the given minimum.
func severityLevelsForSPL(minSeverity string) []string {
	allSPL := []struct {
		splLevel string
		severity string
	}{
		{"critical", logsift.SeverityCritical},
		{"fatal", logsift.SeverityCritical},
		{"error", logsift.SeverityError},
		{"err", logsift.SeverityError},
		{"warn", logsift.SeverityWarn},
		{"warning", logsift.SeverityWarn},
		{"info", logsift.SeverityInfo},
		{"debug", logsift.SeverityDebug},
		{"trace", logsift.SeverityTrace},
	}
	minIdx := logsift.SeverityIndex(minSeverity)
	var result []string
	for _, spl := range allSPL {
		if logsift.SeverityIndex(spl.severity) >= minIdx {
			result = append(result, spl.splLevel)
		}
	}
	return result
}

