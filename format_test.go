package logsift

import (
	"strings"
	"testing"
	"time"
)

func TestFormatText_Basic(t *testing.T) {
	now := time.Now()
	result := &ReductionResult{
		Clusters: []Cluster{
			{
				Template:  "PANIC: nil pointer dereference in handler <*>",
				Severity:  SeverityCritical,
				Count:     1,
				FirstSeen: now,
				LastSeen:  now,
				Examples:  []string{"PANIC: nil pointer dereference in handler processOrder"},
			},
			{
				Template:  "GET /api/health HTTP/1.1 200 <*>",
				Severity:  SeverityInfo,
				Count:     847,
				FirstSeen: now.Add(-15 * time.Minute),
				LastSeen:  now,
				Examples:  []string{"GET /api/health HTTP/1.1 200 12ms"},
			},
		},
		RawCount:   1247,
		TokensUsed: 340,
		HasMore:    false,
	}

	output := FormatText(result, "cloudwatch", "/aws/lambda/api", "15m")

	// Should contain header
	if !strings.Contains(output, "[search_logs]") {
		t.Error("output should contain [search_logs] header")
	}
	if !strings.Contains(output, "1,247 entries") {
		t.Error("output should contain formatted entry count")
	}
	if !strings.Contains(output, "2 clusters") {
		t.Error("output should contain cluster count")
	}

	// Should contain clusters in order
	criticalIdx := strings.Index(output, "CRITICAL")
	infoIdx := strings.Index(output, "INFO")
	if criticalIdx < 0 || infoIdx < 0 {
		t.Error("output should contain both CRITICAL and INFO severities")
	}
	if criticalIdx > infoIdx {
		t.Error("CRITICAL should appear before INFO (signal-first)")
	}

	// Should contain token footer
	if !strings.Contains(output, "tokens]") {
		t.Error("output should contain token count footer")
	}
}

func TestFormatText_ZeroResults(t *testing.T) {
	result := &ReductionResult{
		Clusters: nil,
		RawCount: 0,
	}

	output := FormatText(result, "cloudwatch", "/aws/lambda/api", "15m")

	if !strings.Contains(output, "0 entries found") {
		t.Error("zero result output should contain '0 entries found'")
	}
	if !strings.Contains(output, "list_log_sources") {
		t.Error("zero result output should suggest using list_log_sources")
	}
}

func TestFormatJSON(t *testing.T) {
	now := time.Now()
	result := &ReductionResult{
		Clusters: []Cluster{
			{
				Template:  "error occurred",
				Severity:  SeverityError,
				Count:     3,
				FirstSeen: now,
				LastSeen:  now,
				Examples:  []string{"error occurred during processing"},
			},
		},
		RawCount:   100,
		TokensUsed: 200,
		HasMore:    false,
	}

	output := FormatJSON(result, "datadog", "main-index", "1h")

	if !strings.Contains(output, `"summary"`) {
		t.Error("JSON output should contain summary field")
	}
	if !strings.Contains(output, `"clusters"`) {
		t.Error("JSON output should contain clusters field")
	}
	if !strings.Contains(output, `"tokens_used"`) {
		t.Error("JSON output should contain tokens_used field")
	}
}

func TestFormatTimeout(t *testing.T) {
	output := FormatTimeout("cloudwatch", "30s")
	if !strings.Contains(output, "Timeout") {
		t.Error("timeout output should contain 'Timeout'")
	}
	if !strings.Contains(output, "cloudwatch") {
		t.Error("timeout output should contain provider name")
	}
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{1247, "1,247"},
		{10000, "10,000"},
		{1000000, "1,000,000"},
	}

	for _, tt := range tests {
		got := formatNumber(tt.n)
		if got != tt.want {
			t.Errorf("formatNumber(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestCursorEncodeDecode(t *testing.T) {
	cursor := &PaginationCursor{
		Provider:      "cloudwatch",
		ProviderToken: "next-token-123",
		ClusterOffset: 5,
	}

	encoded := EncodeCursor(cursor)
	decoded, err := DecodeCursor(encoded)
	if err != nil {
		t.Fatalf("DecodeCursor failed: %v", err)
	}

	if decoded.Provider != cursor.Provider {
		t.Errorf("Provider: got %q, want %q", decoded.Provider, cursor.Provider)
	}
	if decoded.ProviderToken != cursor.ProviderToken {
		t.Errorf("ProviderToken: got %q, want %q", decoded.ProviderToken, cursor.ProviderToken)
	}
	if decoded.ClusterOffset != cursor.ClusterOffset {
		t.Errorf("ClusterOffset: got %d, want %d", decoded.ClusterOffset, cursor.ClusterOffset)
	}
}

func TestDecodeCursor_Invalid(t *testing.T) {
	_, err := DecodeCursor("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid cursor")
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		s      string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly ten!", 12, "exactly ten!"},
		{"this is a long string that needs truncation", 20, "this is a long st..."},
	}

	for _, tt := range tests {
		got := TruncateString(tt.s, tt.maxLen)
		if got != tt.want {
			t.Errorf("TruncateString(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
		}
	}
}
