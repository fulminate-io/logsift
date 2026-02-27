// reduce-eval compares logsift's reduced output against raw log reading for
// the same queries. Helps evaluate whether the reduction pipeline preserves
// signal and how much compression it achieves.
//
// Usage:
//
//	LOGSIFT_LOKI_ADDRESS=http://localhost:3100 go run ./cmd/reduce-eval
//	LOGSIFT_LOKI_ADDRESS=http://localhost:3100 go run ./cmd/reduce-eval -source llamacloud-api -range 15m
//	LOGSIFT_LOKI_ADDRESS=http://localhost:3100 go run ./cmd/reduce-eval -all
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	logsift "github.com/fulminate-io/logsift"

	_ "github.com/fulminate-io/logsift/backend/gcp"
	_ "github.com/fulminate-io/logsift/backend/kubernetes"
	_ "github.com/fulminate-io/logsift/backend/loki"
	_ "github.com/fulminate-io/logsift/reducer"
)

func main() {
	source := flag.String("source", "", "log source (namespace). If empty, runs default test cases")
	timeRange := flag.String("range", "15m", "time range (Go duration)")
	provider := flag.String("provider", "loki", "log provider")
	severityMin := flag.String("severity", "INFO", "minimum severity")
	textFilter := flag.String("text", "", "text filter")
	tokenBudget := flag.Int("budget", 4000, "token budget for reduction")
	all := flag.Bool("all", false, "run against all available sources")
	showRaw := flag.Bool("raw", false, "show raw log lines (first 30)")
	flag.Parse()

	creds := buildCredentials()

	available := logsift.Available(creds)
	if len(available) == 0 {
		fmt.Fprintln(os.Stderr, "No backends available. Set LOGSIFT_LOKI_ADDRESS or other env vars.")
		os.Exit(1)
	}

	if !contains(available, *provider) {
		fmt.Fprintf(os.Stderr, "Provider %q not available. Available: %s\n", *provider, strings.Join(available, ", "))
		os.Exit(1)
	}

	if *all {
		runAllSources(creds, *provider, *timeRange, *severityMin, *tokenBudget, *showRaw)
		return
	}

	if *source != "" {
		runCase(creds, testCase{
			Name:        *source,
			Provider:    *provider,
			Source:      *source,
			TimeRange:   *timeRange,
			SeverityMin: *severityMin,
			TextFilter:  *textFilter,
			TokenBudget: *tokenBudget,
		}, *showRaw)
		return
	}

	// Default test cases
	cases := []testCase{
		{Name: "api-all", Provider: *provider, Source: "llamacloud-api", TimeRange: "5m", SeverityMin: "INFO", TokenBudget: 4000},
		{Name: "api-errors", Provider: *provider, Source: "llamacloud-api", TimeRange: "15m", SeverityMin: "ERROR", TokenBudget: 4000},
		{Name: "api-warn+", Provider: *provider, Source: "llamacloud-api", TimeRange: "5m", SeverityMin: "WARN", TokenBudget: 4000},
		{Name: "api-large-budget", Provider: *provider, Source: "llamacloud-api", TimeRange: "5m", SeverityMin: "INFO", TokenBudget: 12000},
		{Name: "jobs-worker", Provider: *provider, Source: "jobs-worker", TimeRange: "5m", SeverityMin: "INFO", TokenBudget: 4000},
		{Name: "frontend", Provider: *provider, Source: "frontend", TimeRange: "5m", SeverityMin: "INFO", TokenBudget: 4000},
		{Name: "temporal-parse", Provider: *provider, Source: "temporal-parse", TimeRange: "5m", SeverityMin: "INFO", TokenBudget: 4000},
	}

	fmt.Println("=" + strings.Repeat("=", 99))
	fmt.Println("REDUCE-EVAL: Comparing raw logs vs reduced output")
	fmt.Println("=" + strings.Repeat("=", 99))
	fmt.Println()

	for _, tc := range cases {
		runCase(creds, tc, *showRaw)
	}

	fmt.Println("Done.")
}

type testCase struct {
	Name        string
	Provider    string
	Source      string
	TimeRange   string
	SeverityMin string
	TextFilter  string
	TokenBudget int
}

func runAllSources(creds *logsift.Credentials, provider, timeRange, severityMin string, tokenBudget int, showRaw bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sources, err := logsift.ListSources(ctx, provider, creds, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list sources: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=" + strings.Repeat("=", 99))
	fmt.Printf("REDUCE-EVAL: All %d sources (%s, %s window, severity >= %s)\n", len(sources), provider, timeRange, severityMin)
	fmt.Println("=" + strings.Repeat("=", 99))
	fmt.Println()

	for _, s := range sources {
		runCase(creds, testCase{
			Name:        s.Name,
			Provider:    provider,
			Source:      s.Name,
			TimeRange:   timeRange,
			SeverityMin: severityMin,
			TokenBudget: tokenBudget,
		}, showRaw)
	}
}

func runCase(creds *logsift.Credentials, tc testCase, showRaw bool) {
	fmt.Printf("--- %s ---\n", tc.Name)
	fmt.Printf("  query: provider=%s source=%s range=%s severity>=%s text=%q budget=%d\n",
		tc.Provider, tc.Source, tc.TimeRange, tc.SeverityMin, tc.TextFilter, tc.TokenBudget)

	duration, err := time.ParseDuration(tc.TimeRange)
	if err != nil {
		duration = 15 * time.Minute
	}

	// Step 1: Fetch raw results
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	q := &logsift.Query{
		Provider:      tc.Provider,
		Source:        tc.Source,
		TextFilter:    tc.TextFilter,
		SeverityMin:   logsift.ParseSeverity(tc.SeverityMin),
		MaxRawEntries: 5000,
		StartTime:     time.Now().Add(-duration),
		EndTime:       time.Now(),
	}

	raw, err := logsift.SearchRaw(ctx, tc.Provider, creds, q)
	if err != nil {
		fmt.Printf("  ERROR fetching raw: %v\n\n", err)
		return
	}

	if len(raw.Entries) == 0 {
		fmt.Printf("  (no entries in window)\n\n")
		return
	}

	// Step 2: Analyze raw entries
	rawStats := analyzeRaw(raw.Entries)
	rawTokens := estimateRawTokens(raw.Entries)

	// Step 3: Run reduction pipeline
	reduced := logsift.Reduce(raw.Entries, logsift.ReductionOpts{
		SeverityMin: logsift.ParseSeverity(tc.SeverityMin),
		TokenBudget: tc.TokenBudget,
	})

	// Step 4: Format reduced output
	reducedText := logsift.FormatText(reduced, tc.Provider, tc.Source, tc.TimeRange)

	// Step 5: Print comparison
	fmt.Println()
	fmt.Printf("  RAW ENTRIES: %d\n", len(raw.Entries))
	fmt.Printf("  Raw tokens (estimated): %d\n", rawTokens)
	fmt.Printf("  Severity breakdown: %s\n", formatSeverityMap(rawStats.severityCounts))
	fmt.Printf("  Unique services: %s\n", formatStringSet(rawStats.services))
	fmt.Printf("  Time span: %s -> %s\n",
		rawStats.earliest.Format("15:04:05"), rawStats.latest.Format("15:04:05"))
	fmt.Println()

	fmt.Printf("  REDUCED: %d clusters, %d tokens used (budget: %d)\n",
		len(reduced.Clusters), reduced.TokensUsed, tc.TokenBudget)
	fmt.Printf("  Compression: %.1f%% token reduction (%d -> %d)\n",
		100*(1-float64(reduced.TokensUsed)/float64(rawTokens)), rawTokens, reduced.TokensUsed)
	fmt.Printf("  Has more: %v\n", reduced.HasMore)
	fmt.Println()

	// Step 6: Show cluster summary
	fmt.Println("  CLUSTERS:")
	for i, c := range reduced.Clusters {
		tmpl := c.Template
		if len(tmpl) > 100 {
			tmpl = tmpl[:100] + "..."
		}
		fmt.Printf("    [%d] %s x%d  %s\n", i+1, c.Severity, c.Count, tmpl)
	}
	fmt.Println()

	// Step 7: Signal loss analysis
	lostSeverities := analyzeLostSignal(raw.Entries, reduced)
	if len(lostSeverities) > 0 {
		fmt.Println("  SIGNAL LOSS (severity counts NOT in output):")
		for sev, count := range lostSeverities {
			fmt.Printf("    %s: %d entries dropped\n", sev, count)
		}
		fmt.Println()
	}

	// Step 8: Show raw lines if requested
	if showRaw {
		limit := 30
		if len(raw.Entries) < limit {
			limit = len(raw.Entries)
		}
		fmt.Printf("  RAW LINES (first %d of %d):\n", limit, len(raw.Entries))
		for i := 0; i < limit; i++ {
			e := raw.Entries[i]
			msg := e.Message
			if len(msg) > 150 {
				msg = msg[:150] + "..."
			}
			fmt.Printf("    %s %s [%s] %s\n", e.Timestamp.Format("15:04:05"), e.Severity, e.Service, msg)
		}
		fmt.Println()
	}

	// Step 9: Show full reduced output
	fmt.Println("  FULL REDUCED OUTPUT:")
	for _, line := range strings.Split(reducedText, "\n") {
		fmt.Printf("    %s\n", line)
	}
	fmt.Println()
}

type rawStats struct {
	severityCounts map[string]int
	services       map[string]bool
	earliest       time.Time
	latest         time.Time
}

func analyzeRaw(entries []logsift.LogEntry) rawStats {
	stats := rawStats{
		severityCounts: make(map[string]int),
		services:       make(map[string]bool),
	}

	for i, e := range entries {
		stats.severityCounts[e.Severity]++
		if e.Service != "" {
			stats.services[e.Service] = true
		}
		if i == 0 || e.Timestamp.Before(stats.earliest) {
			stats.earliest = e.Timestamp
		}
		if i == 0 || e.Timestamp.After(stats.latest) {
			stats.latest = e.Timestamp
		}
	}

	return stats
}

func estimateRawTokens(entries []logsift.LogEntry) int {
	total := 0
	for _, e := range entries {
		// ~4 chars per token, plus overhead for timestamp/severity/service
		total += (len(e.Message) + 60) / 4
	}
	return total
}

func analyzeLostSignal(raw []logsift.LogEntry, reduced *logsift.ReductionResult) map[string]int {
	// Count raw severity distribution
	rawCounts := make(map[string]int)
	for _, e := range raw {
		rawCounts[e.Severity]++
	}

	// Count reduced severity distribution
	reducedCounts := make(map[string]int)
	for _, c := range reduced.Clusters {
		reducedCounts[c.Severity] += c.Count
	}

	// Find what was lost
	lost := make(map[string]int)
	for sev, rawCount := range rawCounts {
		reducedCount := reducedCounts[sev]
		if diff := rawCount - reducedCount; diff > 0 {
			lost[sev] = diff
		}
	}

	// Only report significant losses (errors/warnings)
	result := make(map[string]int)
	for sev, count := range lost {
		if sev == logsift.SeverityError || sev == logsift.SeverityCritical || sev == logsift.SeverityWarn {
			result[sev] = count
		}
	}
	return result
}

func formatSeverityMap(m map[string]int) string {
	order := []string{logsift.SeverityCritical, logsift.SeverityError, logsift.SeverityWarn, logsift.SeverityInfo, logsift.SeverityDebug, logsift.SeverityTrace}
	var parts []string
	for _, sev := range order {
		if count, ok := m[sev]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", sev, count))
		}
	}
	return strings.Join(parts, " ")
}

func formatStringSet(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 10 {
		return fmt.Sprintf("%s (+%d more)", strings.Join(keys[:10], ", "), len(keys)-10)
	}
	return strings.Join(keys, ", ")
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func buildCredentials() *logsift.Credentials {
	creds := &logsift.Credentials{}

	if addr := os.Getenv("LOGSIFT_LOKI_ADDRESS"); addr != "" {
		creds.LokiAddress = addr
	}
	if tenant := os.Getenv("LOGSIFT_LOKI_TENANT_ID"); tenant != "" {
		creds.LokiTenantID = tenant
	}
	if user := os.Getenv("LOGSIFT_LOKI_USERNAME"); user != "" {
		creds.LokiUsername = user
	}
	if pass := os.Getenv("LOGSIFT_LOKI_PASSWORD"); pass != "" {
		creds.LokiPassword = pass
	}

	// GCP
	if projects := os.Getenv("LOGSIFT_GCP_PROJECTS"); projects != "" {
		var saJSON string
		if saPath := os.Getenv("LOGSIFT_GCP_SERVICE_ACCOUNT_JSON"); saPath != "" {
			if data, err := os.ReadFile(saPath); err == nil {
				saJSON = string(data)
			}
		}
		for _, p := range strings.Split(projects, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			creds.GCPProjects = append(creds.GCPProjects, logsift.GCPProjectConfig{
				Name:               p,
				ProjectID:          p,
				ServiceAccountJSON: saJSON,
			})
		}
	}

	return creds
}
