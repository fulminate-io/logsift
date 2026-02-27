package logsift

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// FormatText formats reduction results as human-readable text optimized for LLM reasoning.
func FormatText(result *ReductionResult, provider, source, timeRange string) string {
	var sb strings.Builder

	if len(result.Clusters) == 0 {
		return formatZeroResults(provider, source)
	}

	totalCount := 0
	for _, c := range result.Clusters {
		totalCount += c.Count
	}

	fmt.Fprintf(&sb, "[search_logs] %s entries -> %d clusters (%s window, %s",
		formatNumber(result.RawCount), len(result.Clusters), timeRange, provider)
	if source != "" {
		fmt.Fprintf(&sb, " %s", source)
	}
	sb.WriteString(")\n")

	if result.Sampled {
		fmt.Fprintf(&sb, "  [note: %s of ~%s entries sampled -- results based on sample]\n",
			formatNumber(result.RawCount), formatNumber(result.RawCount*5))
	}
	sb.WriteString("\n")

	for _, c := range result.Clusters {
		writeCluster(&sb, &c)
	}

	fmt.Fprintf(&sb, "[%d/%d tokens]", result.TokensUsed, DefaultTokenBudget)
	if result.Cursor != nil {
		cursorStr := EncodeCursor(result.Cursor)
		fmt.Fprintf(&sb, " [cursor: %s]", cursorStr)
	}
	sb.WriteString("\n")

	return sb.String()
}

func writeCluster(sb *strings.Builder, c *Cluster) {
	sym := SeveritySymbol(c.Severity)

	tpl := truncateString(c.Template, 200)
	if c.Count == 1 {
		fmt.Fprintf(sb, "%s %s [x1] %s\n", sym, c.Severity, tpl)
	} else {
		timeRange := formatTimeRange(c)
		fmt.Fprintf(sb, "%s %s [x%d, %s] %s\n", sym, c.Severity, c.Count, timeRange, tpl)
	}

	// Skip examples when the template has no wildcards (example == template)
	// or when the cluster has no examples (noise-compressed clusters).
	if strings.Contains(c.Template, "<*>") {
		for _, ex := range c.Examples {
			fmt.Fprintf(sb, "  -> %s\n", truncateString(ex, 120))
		}
	}
	sb.WriteString("\n")
}

func formatTimeRange(c *Cluster) string {
	if c.FirstSeen.Equal(c.LastSeen) {
		return c.FirstSeen.Format("15:04:05")
	}
	if c.FirstSeen.Day() == c.LastSeen.Day() {
		return fmt.Sprintf("%s-%s",
			c.FirstSeen.Format("15:04"),
			c.LastSeen.Format("15:04"))
	}
	return fmt.Sprintf("%s - %s",
		c.FirstSeen.Format("Jan 02 15:04"),
		c.LastSeen.Format("Jan 02 15:04"))
}

func formatZeroResults(provider, source string) string {
	return fmt.Sprintf(
		"[search_logs] 0 entries found (searched 15m, 1h, 6h, 24h windows on %s source=%q)\n"+
			"  Suggestions:\n"+
			"  - Verify source name with list_log_sources\n"+
			"  - Broaden text_filter (remove or simplify)\n"+
			"  - Lower severity_min to DEBUG\n"+
			"  - Check if the service was running during this period\n",
		provider, source,
	)
}

// FormatJSON formats reduction results as JSON.
func FormatJSON(result *ReductionResult, provider, source, timeRange string) string {
	type jsonCluster struct {
		Severity  string   `json:"severity"`
		Template  string   `json:"template"`
		Count     int      `json:"count"`
		FirstSeen string   `json:"first_seen"`
		LastSeen  string   `json:"last_seen"`
		Examples  []string `json:"examples"`
	}

	totalCount := 0
	jsonClusters := make([]jsonCluster, len(result.Clusters))
	for i, c := range result.Clusters {
		totalCount += c.Count
		jsonClusters[i] = jsonCluster{
			Severity:  c.Severity,
			Template:  c.Template,
			Count:     c.Count,
			FirstSeen: c.FirstSeen.Format("2006-01-02T15:04:05Z"),
			LastSeen:  c.LastSeen.Format("2006-01-02T15:04:05Z"),
			Examples:  c.Examples,
		}
	}

	var cursorStr string
	if result.Cursor != nil {
		cursorStr = EncodeCursor(result.Cursor)
	}

	output := struct {
		Summary     string        `json:"summary"`
		Clusters    []jsonCluster `json:"clusters"`
		TokensUsed  int           `json:"tokens_used"`
		TokenBudget int           `json:"token_budget"`
		HasMore     bool          `json:"has_more"`
		Cursor      string        `json:"cursor,omitempty"`
		Sampled     bool          `json:"sampled"`
		RawCount    int           `json:"raw_count"`
	}{
		Summary: fmt.Sprintf("%s entries -> %d clusters (%s window, %s %s)",
			formatNumber(result.RawCount), len(result.Clusters), timeRange, provider, source),
		Clusters:    jsonClusters,
		TokensUsed:  result.TokensUsed,
		TokenBudget: DefaultTokenBudget,
		HasMore:     result.HasMore,
		Cursor:      cursorStr,
		Sampled:     result.Sampled,
		RawCount:    result.RawCount,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %s", err)
	}
	return string(data)
}

// FormatTimeout returns a timeout message.
func FormatTimeout(provider string, timeout string) string {
	return fmt.Sprintf("[search_logs] Timeout after %s querying %s. Try narrowing your time_range or adding filters.", timeout, provider)
}

// EncodeCursor serializes a pagination cursor to a base64 string.
func EncodeCursor(c *PaginationCursor) string {
	data, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeCursor deserializes a pagination cursor from a base64 string.
func DecodeCursor(s string) (*PaginationCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor encoding: %w", err)
	}
	var c PaginationCursor
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("invalid cursor data: %w", err)
	}
	return &c, nil
}

func formatNumber(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	var result []byte
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(ch))
	}
	return string(result)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
