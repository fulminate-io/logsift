package logsift

import (
	"testing"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Standard values
		{"TRACE", SeverityTrace},
		{"DEBUG", SeverityDebug},
		{"INFO", SeverityInfo},
		{"WARN", SeverityWarn},
		{"ERROR", SeverityError},
		{"CRITICAL", SeverityCritical},
		// Case insensitive
		{"trace", SeverityTrace},
		{"debug", SeverityDebug},
		{"info", SeverityInfo},
		{"warn", SeverityWarn},
		{"error", SeverityError},
		{"critical", SeverityCritical},
		// Aliases
		{"WARNING", SeverityWarn},
		{"ERR", SeverityError},
		{"FATAL", SeverityError},
		{"SEVERE", SeverityError},
		{"CRIT", SeverityCritical},
		{"ALERT", SeverityCritical},
		{"EMERGENCY", SeverityCritical},
		{"EMERG", SeverityCritical},
		{"PANIC", SeverityCritical},
		{"NOTICE", SeverityInfo},
		{"INFORMATION", SeverityInfo},
		{"DBG", SeverityDebug},
		// Unknown defaults to INFO
		{"UNKNOWN", SeverityInfo},
		{"", SeverityInfo},
		{"  ", SeverityInfo},
		// Whitespace trimming
		{"  ERROR  ", SeverityError},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseSeverity(tt.input)
			if got != tt.want {
				t.Errorf("ParseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSeverityAtLeast(t *testing.T) {
	tests := []struct {
		severity    string
		minSeverity string
		want        bool
	}{
		{SeverityError, SeverityInfo, true},
		{SeverityInfo, SeverityInfo, true},
		{SeverityDebug, SeverityInfo, false},
		{SeverityCritical, SeverityError, true},
		{SeverityTrace, SeverityCritical, false},
	}

	for _, tt := range tests {
		t.Run(tt.severity+">="+tt.minSeverity, func(t *testing.T) {
			got := SeverityAtLeast(tt.severity, tt.minSeverity)
			if got != tt.want {
				t.Errorf("SeverityAtLeast(%q, %q) = %v, want %v", tt.severity, tt.minSeverity, got, tt.want)
			}
		})
	}
}

func TestSeveritySymbol(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{SeverityCritical, "!!"},
		{SeverityError, "!!"},
		{SeverityWarn, "!"},
		{SeverityInfo, " "},
		{SeverityDebug, " "},
		{SeverityTrace, " "},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := SeveritySymbol(tt.severity)
			if got != tt.want {
				t.Errorf("SeveritySymbol(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}
