package axiom

import (
	"strings"
	"testing"

	logsift "github.com/fulminate-io/logsift"
	"github.com/axiomhq/axiom-go/axiom/query"
)

func TestAvailable(t *testing.T) {
	b := &axiomBackend{}

	tests := []struct {
		name   string
		creds  *logsift.Credentials
		expect bool
	}{
		{"nil creds", nil, false},
		{"empty creds", &logsift.Credentials{}, false},
		{"token set", &logsift.Credentials{AxiomToken: "xaat-test"}, true},
		{"instance set", &logsift.Credentials{
			AxiomInstances: []logsift.AxiomInstanceConfig{
				{Name: "prod", Token: "xaat-prod"},
			},
		}, true},
		{"instance without token", &logsift.Credentials{
			AxiomInstances: []logsift.AxiomInstanceConfig{
				{Name: "prod"},
			},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := b.Available(tt.creds)
			if got != tt.expect {
				t.Errorf("Available() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestResolveInstances(t *testing.T) {
	b := &axiomBackend{}

	t.Run("nil creds", func(t *testing.T) {
		got := b.resolveInstances(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("flat fields", func(t *testing.T) {
		creds := &logsift.Credentials{
			AxiomToken: "xaat-test",
			AxiomOrgID: "org-123",
			AxiomURL:   "https://api.eu.axiom.co",
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "default" {
			t.Errorf("name = %q, want %q", got[0].name, "default")
		}
		if got[0].token != "xaat-test" {
			t.Errorf("token = %q, want %q", got[0].token, "xaat-test")
		}
		if got[0].orgID != "org-123" {
			t.Errorf("orgID = %q, want %q", got[0].orgID, "org-123")
		}
		if got[0].url != "https://api.eu.axiom.co" {
			t.Errorf("url = %q, want %q", got[0].url, "https://api.eu.axiom.co")
		}
	})

	t.Run("multi-instance preferred over flat", func(t *testing.T) {
		creds := &logsift.Credentials{
			AxiomToken: "xaat-flat",
			AxiomInstances: []logsift.AxiomInstanceConfig{
				{Name: "prod", Token: "xaat-prod"},
				{Name: "staging", Token: "xaat-staging"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 2 {
			t.Fatalf("expected 2 instances, got %d", len(got))
		}
		if got[0].name != "prod" || got[1].name != "staging" {
			t.Errorf("unexpected instance names: %v, %v", got[0].name, got[1].name)
		}
	})

	t.Run("skip instances without token", func(t *testing.T) {
		creds := &logsift.Credentials{
			AxiomInstances: []logsift.AxiomInstanceConfig{
				{Name: "no-token"},
				{Name: "has-token", Token: "xaat-yes"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "has-token" {
			t.Errorf("name = %q, want %q", got[0].name, "has-token")
		}
	})
}

func TestBuildAPL(t *testing.T) {
	tests := []struct {
		name       string
		query      *logsift.Query
		maxEntries int
		contains   []string
		notContain []string
	}{
		{
			name: "basic query with source",
			query: &logsift.Query{
				Source: "my-dataset",
			},
			maxEntries: 100,
			contains:   []string{"['my-dataset']", "take 100", "order by _time desc"},
		},
		{
			name: "default source when empty",
			query: &logsift.Query{},
			maxEntries: 500,
			contains:   []string{"['*']", "take 500"},
		},
		{
			name: "text filter",
			query: &logsift.Query{
				Source:     "logs",
				TextFilter: "connection refused",
			},
			maxEntries: 100,
			contains:   []string{"['message'] contains \"connection refused\""},
		},
		{
			name: "field filters",
			query: &logsift.Query{
				Source: "logs",
				FieldFilters: map[string]string{
					"namespace": "production",
					"pod":       "api-server",
				},
			},
			maxEntries: 100,
			contains:   []string{"kubernetes.namespace_name", "production", "kubernetes.pod_name", "api-server"},
		},
		{
			name: "severity filter",
			query: &logsift.Query{
				Source:      "logs",
				SeverityMin: "ERROR",
			},
			maxEntries: 100,
			contains:   []string{"['level'] in ("},
		},
		{
			name: "raw query passthrough",
			query: &logsift.Query{
				RawQuery: "['special'] | where custom_field == 'value' | take 50",
			},
			maxEntries: 100,
			contains:   []string{"['special'] | where custom_field == 'value' | take 50"},
			notContain: []string{"order by _time"},
		},
		{
			name: "level field excluded from where clauses",
			query: &logsift.Query{
				Source: "logs",
				FieldFilters: map[string]string{
					"level":   "error",
					"service": "api",
				},
			},
			maxEntries: 100,
			contains:   []string{"['service'] == \"api\""},
			notContain: []string{"['level'] == \"error\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAPL(tt.query, tt.maxEntries)
			for _, s := range tt.contains {
				if !strings.Contains(got, s) {
					t.Errorf("buildAPL() missing %q in:\n%s", s, got)
				}
			}
			for _, s := range tt.notContain {
				if strings.Contains(got, s) {
					t.Errorf("buildAPL() should not contain %q in:\n%s", s, got)
				}
			}
		})
	}
}

func TestNormalizeEntry(t *testing.T) {
	fieldIndex := map[string]int{
		"_time":   0,
		"level":   1,
		"message": 2,
		"service": 3,
		"host":    4,
	}

	t.Run("all fields present", func(t *testing.T) {
		row := query.Row{
			"2026-02-27T10:00:00Z",
			"error",
			"connection refused",
			"payment-api",
			"node-01",
		}
		entry := normalizeEntry(row, fieldIndex)

		if entry.Timestamp.Year() != 2026 {
			t.Errorf("timestamp year = %d, want 2026", entry.Timestamp.Year())
		}
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
		}
		if entry.Message != "connection refused" {
			t.Errorf("message = %q, want %q", entry.Message, "connection refused")
		}
		if entry.Service != "payment-api" {
			t.Errorf("service = %q, want %q", entry.Service, "payment-api")
		}
		if entry.Host != "node-01" {
			t.Errorf("host = %q, want %q", entry.Host, "node-01")
		}
	})

	t.Run("embedded severity detection", func(t *testing.T) {
		row := query.Row{
			"2026-02-27T10:00:00Z",
			"",
			"ERROR something went wrong",
			"",
			"",
		}
		entry := normalizeEntry(row, fieldIndex)
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q (from embedded detection)", entry.Severity, logsift.SeverityError)
		}
	})

	t.Run("map message extraction", func(t *testing.T) {
		row := query.Row{
			"2026-02-27T10:00:00Z",
			"warn",
			map[string]any{"message": "inner msg", "extra": "data"},
			"",
			"",
		}
		entry := normalizeEntry(row, fieldIndex)
		if entry.Message != "inner msg" {
			t.Errorf("message = %q, want %q", entry.Message, "inner msg")
		}
		if entry.Severity != logsift.SeverityWarn {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityWarn)
		}
	})

	t.Run("fallback to msg field", func(t *testing.T) {
		idx := map[string]int{
			"_time": 0,
			"msg":   1,
		}
		row := query.Row{
			"2026-02-27T10:00:00Z",
			"hello from msg field",
		}
		entry := normalizeEntry(row, idx)
		if entry.Message != "hello from msg field" {
			t.Errorf("message = %q, want %q", entry.Message, "hello from msg field")
		}
	})
}

func TestSeverityLevelsAtLeast(t *testing.T) {
	tests := []struct {
		min    string
		expect int // minimum count expected
	}{
		{"CRITICAL", 1},
		{"ERROR", 2},
		{"WARN", 3},
		{"INFO", 4},
		{"DEBUG", 5},
		{"TRACE", 6},
	}

	for _, tt := range tests {
		t.Run(tt.min, func(t *testing.T) {
			got := severityLevelsAtLeast(tt.min)
			if len(got) < tt.expect {
				t.Errorf("severityLevelsAtLeast(%q) = %v (%d), want at least %d levels", tt.min, got, len(got), tt.expect)
			}
		})
	}
}

func TestEscapeAPLString(t *testing.T) {
	tests := []struct {
		input, expect string
	}{
		{`hello`, `hello`},
		{`say "hi"`, `say \"hi\"`},
		{`path\to\file`, `path\\to\\file`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeAPLString(tt.input)
			if got != tt.expect {
				t.Errorf("escapeAPLString(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

func TestRegistered(t *testing.T) {
	backends := logsift.RegisteredBackends()
	found := false
	for _, name := range backends {
		if name == "axiom" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("axiom not found in RegisteredBackends(): %v", backends)
	}
}

func TestAvailableWithToken(t *testing.T) {
	available := logsift.Available(&logsift.Credentials{AxiomToken: "xaat-test"})
	found := false
	for _, name := range available {
		if name == "axiom" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("axiom not found in Available() with token: %v", available)
	}
}
