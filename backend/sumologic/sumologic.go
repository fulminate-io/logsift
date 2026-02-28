package sumologic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("sumologic", &sumoBackend{})
}

// sumoBackend implements logsift.Backend for Sumo Logic via the Search Job API.
type sumoBackend struct{}

// sumoInstance holds the resolved credentials for a single Sumo Logic deployment.
type sumoInstance struct {
	name      string
	accessID  string
	accessKey string
	baseURL   string
}

// Available returns true when at least one instance has an access ID, access key, and URL.
func (b *sumoBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.SumoLogicAccessID != "" && creds.SumoLogicAccessKey != "" && creds.SumoLogicURL != "" {
		return true
	}
	for _, inst := range creds.SumoLogicInstances {
		if inst.AccessID != "" && inst.AccessKey != "" && inst.URL != "" {
			return true
		}
	}
	return false
}

// Search queries logs from all configured Sumo Logic instances.
func (b *sumoBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("sumologic: no instances configured")
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
		return nil, fmt.Errorf("sumologic: all instances failed: %s", strings.Join(errs, "; "))
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available source categories from Sumo Logic instances.
func (b *sumoBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("sumologic: no instances configured")
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

		// Discover source categories via a search query.
		categories, err := b.discoverSourceCategories(ctx, client, inst)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: list sources: %v", inst.name, err))
			continue
		}

		for _, name := range categories {
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
		return nil, fmt.Errorf("sumologic: all instances failed: %s", strings.Join(errs, "; "))
	}

	return sources, nil
}

// resolveInstances builds the list of Sumo Logic instances from credentials.
func (b *sumoBackend) resolveInstances(creds *logsift.Credentials) []sumoInstance {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-instance list.
	if len(creds.SumoLogicInstances) > 0 {
		var instances []sumoInstance
		for _, c := range creds.SumoLogicInstances {
			if c.AccessID == "" || c.AccessKey == "" || c.URL == "" {
				continue
			}
			name := c.Name
			if name == "" {
				name = "sumologic"
			}
			instances = append(instances, sumoInstance{
				name:      name,
				accessID:  c.AccessID,
				accessKey: c.AccessKey,
				baseURL:   strings.TrimRight(c.URL, "/"),
			})
		}
		if len(instances) > 0 {
			return instances
		}
	}

	// Fallback to flat fields.
	if creds.SumoLogicAccessID != "" && creds.SumoLogicAccessKey != "" && creds.SumoLogicURL != "" {
		return []sumoInstance{{
			name:      "default",
			accessID:  creds.SumoLogicAccessID,
			accessKey: creds.SumoLogicAccessKey,
			baseURL:   strings.TrimRight(creds.SumoLogicURL, "/"),
		}}
	}

	return nil
}

// newClient creates an HTTP client with cookie jar (critical for Sumo Logic job routing).
func (b *sumoBackend) newClient(inst sumoInstance) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Jar:     jar,
	}, nil
}

// searchInstance queries a single Sumo Logic instance using the Search Job API.
func (b *sumoBackend) searchInstance(ctx context.Context, inst sumoInstance, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	client, err := b.newClient(inst)
	if err != nil {
		return nil, err
	}

	query := buildSumoQuery(q)

	// Determine time range. The Search Job API requires absolute timestamps
	// (ISO 8601 or epoch ms) — relative strings like "-1h" are not supported.
	now := time.Now().UTC()
	from := now.Add(-1 * time.Hour).Format("2006-01-02T15:04:05")
	to := now.Format("2006-01-02T15:04:05")
	if !q.StartTime.IsZero() {
		from = q.StartTime.UTC().Format("2006-01-02T15:04:05")
	}
	if !q.EndTime.IsZero() {
		to = q.EndTime.UTC().Format("2006-01-02T15:04:05")
	}

	// Create search job.
	jobID, err := b.createSearchJob(ctx, client, inst, query, from, to)
	if err != nil {
		return nil, fmt.Errorf("create job: %w", err)
	}
	defer b.deleteSearchJob(client, inst, jobID) //nolint:errcheck // best-effort cleanup

	// Poll for completion.
	status, err := b.waitForCompletion(ctx, client, inst, jobID)
	if err != nil {
		return nil, fmt.Errorf("wait: %w", err)
	}

	if status.MessageCount == 0 {
		return nil, nil
	}

	// Fetch messages (cap at maxEntries).
	fetchCount := status.MessageCount
	if fetchCount > maxEntries {
		fetchCount = maxEntries
	}

	messages, err := b.getMessages(ctx, client, inst, jobID, fetchCount)
	if err != nil {
		return nil, fmt.Errorf("get messages: %w", err)
	}

	var entries []logsift.LogEntry
	for _, msg := range messages {
		entry := normalizeMessage(msg)

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

// --- Search Job API types ---

type searchJobRequest struct {
	Query           string `json:"query"`
	From            string `json:"from"`
	To              string `json:"to"`
	TimeZone        string `json:"timeZone"`
	AutoParsingMode string `json:"autoParsingMode,omitempty"`
}

type searchJobCreateResponse struct {
	ID string `json:"id"`
}

type searchJobStatus struct {
	State        string `json:"state"`
	MessageCount int    `json:"messageCount"`
	RecordCount  int    `json:"recordCount"`
}

type searchMessage struct {
	Map map[string]string `json:"map"`
}

type searchMessagesResponse struct {
	Messages []searchMessage `json:"messages"`
}

// --- Search Job API methods ---

func (b *sumoBackend) createSearchJob(ctx context.Context, client *http.Client, inst sumoInstance, query, from, to string) (string, error) {
	body, err := json.Marshal(searchJobRequest{
		Query:           query,
		From:            from,
		To:              to,
		TimeZone:        "UTC",
		AutoParsingMode: "AutoParse",
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		inst.baseURL+"/api/v1/search/jobs", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(inst.accessID, inst.accessKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, logsift.TruncateString(string(respBody), 500))
	}

	var result searchJobCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return result.ID, nil
}

func (b *sumoBackend) waitForCompletion(ctx context.Context, client *http.Client, inst sumoInstance, jobID string) (*searchJobStatus, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		status, err := b.getJobStatus(ctx, client, inst, jobID)
		if err != nil {
			return nil, err
		}

		switch status.State {
		case "DONE GATHERING RESULTS":
			return status, nil
		case "CANCELLED":
			return nil, fmt.Errorf("job %s: %s", jobID, status.State)
		}

		// Poll every 5 seconds (job auto-cancels after 20-30s without polling).
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (b *sumoBackend) getJobStatus(ctx context.Context, client *http.Client, inst sumoInstance, jobID string) (*searchJobStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		inst.baseURL+"/api/v1/search/jobs/"+jobID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(inst.accessID, inst.accessKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("status request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status HTTP %d: %s", resp.StatusCode, logsift.TruncateString(string(respBody), 500))
	}

	var status searchJobStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode status: %w", err)
	}
	return &status, nil
}

func (b *sumoBackend) getMessages(ctx context.Context, client *http.Client, inst sumoInstance, jobID string, count int) ([]map[string]string, error) {
	const pageSize = 1000
	var allMessages []map[string]string

	for offset := 0; offset < count; offset += pageSize {
		limit := pageSize
		if offset+limit > count {
			limit = count - offset
		}

		messages, err := b.fetchMessagePage(ctx, client, inst, jobID, offset, limit)
		if err != nil {
			return nil, err
		}
		allMessages = append(allMessages, messages...)
	}

	return allMessages, nil
}

func (b *sumoBackend) fetchMessagePage(ctx context.Context, client *http.Client, inst sumoInstance, jobID string, offset, limit int) ([]map[string]string, error) {
	u, err := url.Parse(inst.baseURL + "/api/v1/search/jobs/" + jobID + "/messages")
	if err != nil {
		return nil, fmt.Errorf("parse messages URL: %w", err)
	}
	qp := u.Query()
	qp.Set("offset", fmt.Sprintf("%d", offset))
	qp.Set("limit", fmt.Sprintf("%d", limit))
	u.RawQuery = qp.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(inst.accessID, inst.accessKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get messages: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("messages HTTP %d: %s", resp.StatusCode, logsift.TruncateString(string(respBody), 500))
	}

	var result searchMessagesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode messages: %w", err)
	}

	var messages []map[string]string
	for _, m := range result.Messages {
		messages = append(messages, m.Map)
	}
	return messages, nil
}

func (b *sumoBackend) deleteSearchJob(client *http.Client, inst sumoInstance, jobID string) error {
	// Use a fresh context with timeout since this is called from defer where the
	// parent context may already be cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		inst.baseURL+"/api/v1/search/jobs/"+jobID, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(inst.accessID, inst.accessKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// discoverSourceCategories uses a search query to find distinct source categories.
func (b *sumoBackend) discoverSourceCategories(ctx context.Context, client *http.Client, inst sumoInstance) ([]string, error) {
	// Use a simple aggregation query to discover categories.
	query := "* | count by _sourceCategory | sort by _count desc | limit 100"
	now := time.Now().UTC()
	from := now.Add(-7 * 24 * time.Hour).Format("2006-01-02T15:04:05")
	to := now.Format("2006-01-02T15:04:05")

	jobID, err := b.createSearchJob(ctx, client, inst, query, from, to)
	if err != nil {
		return nil, err
	}
	defer b.deleteSearchJob(client, inst, jobID) //nolint:errcheck

	status, err := b.waitForCompletion(ctx, client, inst, jobID)
	if err != nil {
		return nil, err
	}

	if status.RecordCount == 0 {
		return nil, nil
	}

	// Fetch records (aggregation results).
	u, err := url.Parse(inst.baseURL + "/api/v1/search/jobs/" + jobID + "/records")
	if err != nil {
		return nil, fmt.Errorf("parse records URL: %w", err)
	}
	qp := u.Query()
	qp.Set("offset", "0")
	qp.Set("limit", "100")
	u.RawQuery = qp.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(inst.accessID, inst.accessKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("records HTTP %d: %s", resp.StatusCode, logsift.TruncateString(string(respBody), 500))
	}

	var result struct {
		Records []struct {
			Map map[string]string `json:"map"`
		} `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode records: %w", err)
	}

	var categories []string
	for _, r := range result.Records {
		if cat, ok := r.Map["_sourceCategory"]; ok && cat != "" {
			categories = append(categories, cat)
		}
	}
	return categories, nil
}

// normalizeMessage converts a Sumo Logic message map into a LogEntry.
func normalizeMessage(msg map[string]string) logsift.LogEntry {
	entry := logsift.LogEntry{
		Timestamp: time.Now(),
		Severity:  logsift.SeverityInfo,
	}

	// Extract timestamp from _messagetime (epoch milliseconds as string).
	if v, ok := msg["_messagetime"]; ok && v != "" {
		if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
			entry.Timestamp = time.UnixMilli(ms).UTC()
		}
	}

	// Extract message from _raw.
	if v, ok := msg["_raw"]; ok && v != "" {
		entry.Message = v
	}

	// Extract severity from common level fields.
	for _, key := range []string{"_loglevel", "level", "log_level", "severity"} {
		if v, ok := msg[key]; ok && v != "" {
			entry.Severity = logsift.ParseSeverity(v)
			break
		}
	}

	// Extract host from _sourceHost.
	if v, ok := msg["_sourceHost"]; ok && v != "" {
		entry.Host = v
	}

	// Extract service from _sourceCategory.
	if v, ok := msg["_sourceCategory"]; ok && v != "" {
		entry.Service = v
	}

	// Fall back to embedded severity detection.
	if entry.Severity == logsift.SeverityInfo {
		if embedded := logsift.DetectEmbeddedSeverity(entry.Message); embedded != "" {
			entry.Severity = embedded
		}
	}

	return entry
}

// buildSumoQuery constructs a Sumo Logic query from the structured Query.
func buildSumoQuery(q *logsift.Query) string {
	// If raw query is set, use it directly.
	if q.RawQuery != "" {
		return q.RawQuery
	}

	var parts []string

	// Source filter (as _sourceCategory).
	if q.Source != "" {
		parts = append(parts, fmt.Sprintf("_sourceCategory=%s", logsift.SanitizeSourceName(q.Source)))
	} else {
		parts = append(parts, "*")
	}

	// Map canonical field filters to Sumo Logic-native names.
	mapped := logsift.MapFieldFilters(q.FieldFilters, logsift.FieldMappingSumoLogic)
	var filterClauses []string
	for field, value := range mapped {
		// Skip level — handled via severity filter below.
		if field == "level" || field == "severity" || field == "_loglevel" {
			continue
		}
		// Metadata fields (starting with _) go in the keyword clause.
		if strings.HasPrefix(field, "_") {
			parts = append(parts, fmt.Sprintf("%s=%s", field, value))
		} else {
			filterClauses = append(filterClauses, fmt.Sprintf("where %s=%q", field, value))
		}
	}

	// Text filter as keyword search.
	if q.TextFilter != "" {
		parts = append(parts, fmt.Sprintf("%q", q.TextFilter))
	}

	query := strings.Join(parts, " ")

	// Add json auto for structured parsing.
	query += " | json auto"

	// Add field filter clauses.
	for _, clause := range filterClauses {
		query += " | " + clause
	}

	// Add severity filter.
	if q.SeverityMin != "" {
		sevLevels := severityLevelsForSumo(q.SeverityMin)
		if len(sevLevels) > 0 {
			var orClauses []string
			for _, sev := range sevLevels {
				orClauses = append(orClauses, fmt.Sprintf("level=%q", sev))
			}
			query += " | where " + strings.Join(orClauses, " or ")
		}
	}

	return query
}

// severityLevelsForSumo returns severity level strings at or above the given minimum.
func severityLevelsForSumo(minSeverity string) []string {
	allSumo := []struct {
		sumoLevel string
		severity  string
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
	for _, s := range allSumo {
		if logsift.SeverityIndex(s.severity) >= minIdx {
			result = append(result, s.sumoLevel)
		}
	}
	return result
}

