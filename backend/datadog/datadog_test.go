package datadog

import (
	"strings"
	"testing"

	logsift "github.com/fulminate-io/logsift"
)

func TestAvailable(t *testing.T) {
	b := &datadogBackend{}

	tests := []struct {
		name   string
		creds  *logsift.Credentials
		expect bool
	}{
		{"nil creds", nil, false},
		{"empty creds", &logsift.Credentials{}, false},
		{"only api key", &logsift.Credentials{DatadogAPIKey: "abc"}, false},
		{"only app key", &logsift.Credentials{DatadogAppKey: "abc"}, false},
		{"both keys", &logsift.Credentials{DatadogAPIKey: "abc", DatadogAppKey: "def"}, true},
		{"instance with both keys", &logsift.Credentials{
			DatadogInstances: []logsift.DatadogInstanceConfig{
				{Name: "prod", APIKey: "abc", AppKey: "def"},
			},
		}, true},
		{"instance missing app key", &logsift.Credentials{
			DatadogInstances: []logsift.DatadogInstanceConfig{
				{Name: "prod", APIKey: "abc"},
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
	b := &datadogBackend{}

	t.Run("nil creds", func(t *testing.T) {
		got := b.resolveInstances(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("flat fields", func(t *testing.T) {
		creds := &logsift.Credentials{
			DatadogAPIKey: "api-123",
			DatadogAppKey: "app-456",
			DatadogSite:   "datadoghq.eu",
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "default" {
			t.Errorf("name = %q, want %q", got[0].name, "default")
		}
		if got[0].apiKey != "api-123" {
			t.Errorf("apiKey = %q, want %q", got[0].apiKey, "api-123")
		}
		if got[0].appKey != "app-456" {
			t.Errorf("appKey = %q, want %q", got[0].appKey, "app-456")
		}
		if got[0].site != "datadoghq.eu" {
			t.Errorf("site = %q, want %q", got[0].site, "datadoghq.eu")
		}
	})

	t.Run("multi-instance preferred over flat", func(t *testing.T) {
		creds := &logsift.Credentials{
			DatadogAPIKey: "flat-api",
			DatadogAppKey: "flat-app",
			DatadogInstances: []logsift.DatadogInstanceConfig{
				{Name: "prod", APIKey: "prod-api", AppKey: "prod-app"},
				{Name: "staging", APIKey: "stg-api", AppKey: "stg-app"},
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

	t.Run("skip instances without both keys", func(t *testing.T) {
		creds := &logsift.Credentials{
			DatadogInstances: []logsift.DatadogInstanceConfig{
				{Name: "no-app", APIKey: "abc"},
				{Name: "no-api", AppKey: "def"},
				{Name: "has-both", APIKey: "abc", AppKey: "def"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "has-both" {
			t.Errorf("name = %q, want %q", got[0].name, "has-both")
		}
	})
}

func TestBuildQuery(t *testing.T) {
	tests := []struct {
		name       string
		query      *logsift.Query
		contains   []string
		notContain []string
	}{
		{
			name:     "empty query returns wildcard",
			query:    &logsift.Query{},
			contains: []string{"*"},
		},
		{
			name: "text filter quoted",
			query: &logsift.Query{
				TextFilter: "connection refused",
			},
			contains: []string{`"connection refused"`},
		},
		{
			name: "field filters mapped",
			query: &logsift.Query{
				FieldFilters: map[string]string{
					"namespace": "production",
					"service":   "payment-api",
				},
			},
			contains: []string{"kube_namespace:production", "service:payment-api"},
		},
		{
			name: "severity filter",
			query: &logsift.Query{
				SeverityMin: "ERROR",
			},
			contains:   []string{"status:error", "status:critical", "status:emergency"},
			notContain: []string{"status:warn", "status:info"},
		},
		{
			name: "raw query passthrough",
			query: &logsift.Query{
				RawQuery: "service:custom AND @http.status_code:500",
			},
			contains:   []string{"service:custom AND @http.status_code:500"},
			notContain: []string{"*"},
		},
		{
			name: "level field excluded from field filters",
			query: &logsift.Query{
				FieldFilters: map[string]string{
					"level":   "error",
					"service": "api",
				},
			},
			contains:   []string{"service:api"},
			notContain: []string{"status:error"},
		},
		{
			name: "custom attribute gets @ prefix",
			query: &logsift.Query{
				FieldFilters: map[string]string{
					"http.status_code": "500",
				},
			},
			contains: []string{"@http.status_code:500"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildQuery(tt.query)
			for _, s := range tt.contains {
				if !strings.Contains(got, s) {
					t.Errorf("buildQuery() missing %q in: %s", s, got)
				}
			}
			for _, s := range tt.notContain {
				if strings.Contains(got, s) {
					t.Errorf("buildQuery() should not contain %q in: %s", s, got)
				}
			}
		})
	}
}

func TestSeverityLevelsForDD(t *testing.T) {
	tests := []struct {
		min    string
		expect int // minimum count expected
	}{
		{"CRITICAL", 3}, // emergency, alert, critical
		{"ERROR", 4},    // + error
		{"WARN", 5},     // + warn
		{"INFO", 6},     // + info
		{"DEBUG", 7},    // + debug
		{"TRACE", 8},    // + trace
	}

	for _, tt := range tests {
		t.Run(tt.min, func(t *testing.T) {
			got := severityLevelsForDD(tt.min)
			if len(got) < tt.expect {
				t.Errorf("severityLevelsForDD(%q) = %v (%d), want at least %d", tt.min, got, len(got), tt.expect)
			}
		})
	}
}

func TestEscapeValue(t *testing.T) {
	tests := []struct {
		input, expect string
	}{
		{"simple", "simple"},
		{"has space", `"has space"`},
		{`has"quote`, `"has\"quote"`},
		{"colon:value", `"colon:value"`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeValue(tt.input)
			if got != tt.expect {
				t.Errorf("escapeValue(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

func TestRegistered(t *testing.T) {
	backends := logsift.RegisteredBackends()
	found := false
	for _, name := range backends {
		if name == "datadog" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("datadog not found in RegisteredBackends(): %v", backends)
	}
}

func TestAvailableWithBothKeys(t *testing.T) {
	available := logsift.Available(&logsift.Credentials{
		DatadogAPIKey: "test-api",
		DatadogAppKey: "test-app",
	})
	found := false
	for _, name := range available {
		if name == "datadog" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("datadog not found in Available() with both keys: %v", available)
	}
}
