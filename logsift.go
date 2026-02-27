// Package logsift reduces thousands of raw log lines into compact, LLM-friendly
// summaries. A 7-layer pipeline — deduplication, Drain clustering,
// language-specific consolidation, stack trace grouping, signal-priority
// sorting, and token-budget truncation — typically achieves 95-99% token
// reduction while preserving all diagnostic signal.
//
// Backends are registered via blank imports:
//
//	import _ "github.com/fulminate-io/logsift/backend/kubernetes"
//	import _ "github.com/fulminate-io/logsift/backend/gcp"
//
// Then use [Search] or [SearchRaw] + [Reduce] to query and reduce logs.
package logsift

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Search queries the specified provider, applies the full reduction pipeline,
// and returns a compact result ready for LLM consumption. It auto-expands the
// time window if the initial query returns zero results.
func Search(ctx context.Context, provider string, creds *Credentials, input *SearchLogsInput) (string, error) {
	backend, ok := Get(provider)
	if !ok {
		return "", fmt.Errorf("unknown provider %q; registered: %s",
			provider, strings.Join(RegisteredBackends(), ", "))
	}
	if !backend.Available(creds) {
		available := Available(creds)
		if len(available) == 0 {
			return "", fmt.Errorf("no credentials configured for %q", provider)
		}
		return "", fmt.Errorf("no credentials configured for %q; available: %s",
			provider, strings.Join(available, ", "))
	}

	q := &Query{
		Provider:      provider,
		TextFilter:    input.TextFilter,
		FieldFilters:  input.FieldFilters,
		SeverityMin:   input.SeverityMin,
		Source:        input.Source,
		RawQuery:      input.RawQuery,
		MaxRawEntries: 10_000,
		TokenBudget:   input.TokenBudget,
	}

	if q.SeverityMin == "" {
		q.SeverityMin = SeverityInfo
	} else {
		q.SeverityMin = ParseSeverity(q.SeverityMin)
	}
	if q.TokenBudget <= 0 {
		q.TokenBudget = DefaultTokenBudget
	}

	// Parse cursor if provided.
	var cursor *PaginationCursor
	if input.Cursor != "" {
		var err error
		cursor, err = DecodeCursor(input.Cursor)
		if err != nil {
			return "", fmt.Errorf("invalid cursor: %w", err)
		}
		if cursor.Provider != provider {
			return "", fmt.Errorf("cursor was created for provider %q but used with %q",
				cursor.Provider, provider)
		}
	}

	timeRangeStr := input.TimeRange
	if timeRangeStr == "" {
		timeRangeStr = "15m"
	}

	// Auto-expand time window on zero results.
	results, guidance, err := autoExpandWindow(ctx, backend, creds, q, timeRangeStr)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return FormatTimeout(provider, "30s"), nil
		}
		return "", fmt.Errorf("error querying %s: %w", provider, err)
	}
	if guidance != "" {
		return guidance, nil
	}

	// Run reduction pipeline.
	sampled := results.TotalEstimate > len(results.Entries) && results.TotalEstimate > 0
	reduction := Reduce(results.Entries, ReductionOpts{
		SeverityMin: q.SeverityMin,
		TokenBudget: q.TokenBudget,
		Cursor:      cursor,
	})
	reduction.Sampled = sampled

	// Build cursor for pagination.
	if reduction.HasMore || results.ProviderToken != "" {
		clusterOffset := 0
		if cursor != nil {
			clusterOffset = cursor.ClusterOffset
		}
		reduction.Cursor = &PaginationCursor{
			Provider:      provider,
			ProviderToken: results.ProviderToken,
			ClusterOffset: clusterOffset + len(reduction.Clusters),
		}
	}

	if input.Mode == "json" {
		return FormatJSON(reduction, provider, input.Source, timeRangeStr), nil
	}
	return FormatText(reduction, provider, input.Source, timeRangeStr), nil
}

// SearchRaw queries the specified provider and returns raw log entries
// without applying the reduction pipeline.
func SearchRaw(ctx context.Context, provider string, creds *Credentials, q *Query) (*RawResults, error) {
	backend, ok := Get(provider)
	if !ok {
		return nil, fmt.Errorf("unknown provider %q; registered: %s",
			provider, strings.Join(RegisteredBackends(), ", "))
	}
	if !backend.Available(creds) {
		return nil, fmt.Errorf("no credentials configured for %q", provider)
	}
	return backend.Search(ctx, creds, q)
}

// ListSources returns available log sources for the specified provider.
func ListSources(ctx context.Context, provider string, creds *Credentials, prefix string) ([]SourceInfo, error) {
	backend, ok := Get(provider)
	if !ok {
		return nil, fmt.Errorf("unknown provider %q; registered: %s",
			provider, strings.Join(RegisteredBackends(), ", "))
	}
	if !backend.Available(creds) {
		return nil, fmt.Errorf("no credentials configured for %q", provider)
	}
	return backend.ListSources(ctx, creds, prefix)
}

func autoExpandWindow(ctx context.Context, b Backend, creds *Credentials, q *Query, requestedRange string) (*RawResults, string, error) {
	duration, err := time.ParseDuration(requestedRange)
	if err != nil || duration <= 0 {
		duration = 15 * time.Minute
	}

	windows := expandWindows(duration)

	for _, w := range windows {
		q.EndTime = time.Now()
		q.StartTime = q.EndTime.Add(-w)

		results, err := b.Search(ctx, creds, q)
		if err != nil {
			return nil, "", err
		}
		if len(results.Entries) > 0 {
			return results, "", nil
		}
	}

	guidance := fmt.Sprintf(
		"[search_logs] 0 entries found (searched %s windows on %s source=%q)\n"+
			"  Suggestions:\n"+
			"  - Verify source name with list_log_sources\n"+
			"  - Broaden text_filter (remove or simplify)\n"+
			"  - Lower severity_min to DEBUG\n"+
			"  - Check if the service was running during this period\n",
		formatWindowList(windows), q.Provider, q.Source,
	)
	return &RawResults{}, guidance, nil
}

func expandWindows(requested time.Duration) []time.Duration {
	standard := []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	var windows []time.Duration
	windows = append(windows, requested)
	for _, w := range standard {
		if w > requested {
			windows = append(windows, w)
		}
	}
	return windows
}

func formatWindowList(windows []time.Duration) string {
	parts := make([]string, len(windows))
	for i, w := range windows {
		if w >= time.Hour {
			parts[i] = fmt.Sprintf("%dh", int(w.Hours()))
		} else {
			parts[i] = fmt.Sprintf("%dm", int(w.Minutes()))
		}
	}
	var sb strings.Builder
	for i, p := range parts {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(p)
	}
	return sb.String()
}
