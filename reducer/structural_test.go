package reducer

import (
	"strings"
	"testing"
	"time"

	"github.com/fulminate-io/logsift"
)

func TestIsStructuralFragment(t *testing.T) {
	tests := []struct {
		name string
		c    logsift.Cluster
		want bool
	}{
		{"JSON key fragment", logsift.Cluster{Template: `  "coresToReplicas":`}, true},
		{"JSON key-value empty array", logsift.Cluster{Template: `  "coresToReplicas": [],`}, true},
		{"JSON key-value empty object", logsift.Cluster{Template: `"config": {}`}, true},
		{"closing bracket", logsift.Cluster{Template: "],"}, true},
		{"opening bracket", logsift.Cluster{Template: "["}, true},
		{"empty braces", logsift.Cluster{Template: "{}"}, true},
		{"closing brace", logsift.Cluster{Template: "}"}, true},
		{"caret only", logsift.Cluster{Template: "^"}, true},
		{"closing paren", logsift.Cluster{Template: ")"}, true},
		{"tree characters", logsift.Cluster{Template: "│"}, true},
		{"tree branch", logsift.Cluster{Template: "├──"}, true},
		{"wildcard heavy", logsift.Cluster{Template: "<*> <*> <*> <*>"}, true},
		{"tree prefix with content", logsift.Cluster{Template: "│     └─ mem limit  : 976.6K"}, true},
		{"tree prefix pipe content", logsift.Cluster{Template: "│ some status output"}, true},
		{"real error message", logsift.Cluster{Template: "connection timeout after 3200ms"}, false},
		{"real log with JSON", logsift.Cluster{Template: `{"level":"error","msg":"request failed"}`}, false},
		{"meaningful short message", logsift.Cluster{Template: "Terminated"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isStructuralFragment(&tt.c); got != tt.want {
				t.Errorf("isStructuralFragment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStructuralConsolidator(t *testing.T) {
	c := &structuralConsolidator{}
	now := time.Now()

	t.Run("merges structural fragments into single cluster", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "real error message", Severity: logsift.SeverityError, Count: 5, FirstSeen: now, LastSeen: now},
			{Template: "{", Severity: logsift.SeverityError, Count: 2, FirstSeen: now, LastSeen: now},
			{Template: `  "coresToReplicas":`, Severity: logsift.SeverityError, Count: 2, FirstSeen: now, LastSeen: now.Add(100 * time.Millisecond)},
			{Template: `  "coresToReplicas": [],`, Severity: logsift.SeverityError, Count: 2, FirstSeen: now, LastSeen: now.Add(200 * time.Millisecond)},
			{Template: "}", Severity: logsift.SeverityError, Count: 2, FirstSeen: now, LastSeen: now.Add(300 * time.Millisecond)},
		}

		result := c.Consolidate(clusters)

		if len(result) != 2 {
			t.Fatalf("expected 2 clusters, got %d", len(result))
		}
		if result[0].Template != "real error message" {
			t.Errorf("first cluster should be normal, got %q", result[0].Template)
		}

		structural := result[1]
		if !strings.Contains(structural.Template, "Structural output") {
			t.Errorf("merged template should mention structural, got %q", structural.Template)
		}
		if structural.Severity != logsift.SeverityInfo {
			t.Errorf("structural severity should be INFO, got %s", structural.Severity)
		}
		if structural.Count != 8 {
			t.Errorf("merged count: got %d, want 8", structural.Count)
		}
	})

	t.Run("single fragment kept as-is", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "real error", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now},
			{Template: "}", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now},
		}

		result := c.Consolidate(clusters)
		if len(result) != 2 {
			t.Fatalf("expected 2 clusters (no consolidation with single fragment), got %d", len(result))
		}
	})
}

func TestIsPunctuationOnly(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"],", true},
		{"{}", true},
		{"}", true},
		{"[", true},
		{")", true},
		{"^", true},
		{"", false},
		{"hello", false},
		{"{ }", true},
		{"│", true},
		{"├──", true},
		{"│├└─", true},
		{"{level:error}", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isPunctuationOnly(tt.input); got != tt.want {
				t.Errorf("isPunctuationOnly(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
