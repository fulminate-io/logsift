package splunk

import (
	"net/http"
	"strings"
	"testing"

	logsift "github.com/fulminate-io/logsift"
)

func TestAvailable(t *testing.T) {
	b := &splunkBackend{}

	tests := []struct {
		name   string
		creds  *logsift.Credentials
		expect bool
	}{
		{"nil creds", nil, false},
		{"empty creds", &logsift.Credentials{}, false},
		{"url set", &logsift.Credentials{
			SplunkURL: "https://splunk.example.com:8089",
		}, true},
		{"instance with url", &logsift.Credentials{
			SplunkInstances: []logsift.SplunkInstanceConfig{
				{Name: "prod", URL: "https://prod:8089"},
			},
		}, true},
		{"instance without url", &logsift.Credentials{
			SplunkInstances: []logsift.SplunkInstanceConfig{
				{Name: "empty"},
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
	b := &splunkBackend{}

	t.Run("nil creds", func(t *testing.T) {
		got := b.resolveInstances(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("flat fields", func(t *testing.T) {
		creds := &logsift.Credentials{
			SplunkURL:      "https://splunk:8089",
			SplunkToken:    "my-token",
			SplunkUsername: "admin",
			SplunkPassword: "changeme",
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "default" {
			t.Errorf("name = %q, want %q", got[0].name, "default")
		}
		if got[0].baseURL != "https://splunk:8089" {
			t.Errorf("baseURL = %q, want %q", got[0].baseURL, "https://splunk:8089")
		}
		if got[0].token != "my-token" {
			t.Errorf("token = %q, want %q", got[0].token, "my-token")
		}
	})

	t.Run("multi-instance preferred", func(t *testing.T) {
		creds := &logsift.Credentials{
			SplunkURL: "https://flat:8089",
			SplunkInstances: []logsift.SplunkInstanceConfig{
				{Name: "prod", URL: "https://prod:8089"},
				{Name: "staging", URL: "https://staging:8089"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 2 {
			t.Fatalf("expected 2 instances, got %d", len(got))
		}
		if got[0].name != "prod" || got[1].name != "staging" {
			t.Errorf("unexpected names: %v, %v", got[0].name, got[1].name)
		}
	})

	t.Run("skip instances without url", func(t *testing.T) {
		creds := &logsift.Credentials{
			SplunkInstances: []logsift.SplunkInstanceConfig{
				{Name: "no-url"},
				{Name: "has-url", URL: "https://valid:8089"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "has-url" {
			t.Errorf("name = %q, want %q", got[0].name, "has-url")
		}
	})

	t.Run("default name when empty", func(t *testing.T) {
		creds := &logsift.Credentials{
			SplunkInstances: []logsift.SplunkInstanceConfig{
				{URL: "https://splunk:8089"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "splunk" {
			t.Errorf("name = %q, want %q", got[0].name, "splunk")
		}
	})
}

func TestBuildSPL(t *testing.T) {
	t.Run("default index", func(t *testing.T) {
		q := &logsift.Query{}
		spl := buildSPL(q, 100)
		if !strings.Contains(spl, "index=*") {
			t.Errorf("expected index=* in: %s", spl)
		}
		if !strings.Contains(spl, "head 100") {
			t.Errorf("expected head 100 in: %s", spl)
		}
		if !strings.Contains(spl, "sort -_time") {
			t.Errorf("expected sort in: %s", spl)
		}
	})

	t.Run("custom index", func(t *testing.T) {
		q := &logsift.Query{Source: "main"}
		spl := buildSPL(q, 50)
		if !strings.Contains(spl, "index=main") {
			t.Errorf("expected index=main in: %s", spl)
		}
		if strings.Contains(spl, "index=*") {
			t.Errorf("should not contain default index in: %s", spl)
		}
	})

	t.Run("text filter", func(t *testing.T) {
		q := &logsift.Query{TextFilter: "connection refused"}
		spl := buildSPL(q, 100)
		if !strings.Contains(spl, "connection refused") {
			t.Errorf("expected text filter in: %s", spl)
		}
	})

	t.Run("field filters mapped", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"namespace": "production",
				"host":      "web-01",
			},
		}
		spl := buildSPL(q, 100)
		if !strings.Contains(spl, "namespace=") {
			t.Errorf("expected namespace filter in: %s", spl)
		}
		if !strings.Contains(spl, "host=") {
			t.Errorf("expected host filter in: %s", spl)
		}
	})

	t.Run("severity filter", func(t *testing.T) {
		q := &logsift.Query{SeverityMin: "ERROR"}
		spl := buildSPL(q, 100)
		if !strings.Contains(spl, "level=") {
			t.Errorf("expected level filter in: %s", spl)
		}
		if !strings.Contains(spl, "error") {
			t.Errorf("expected 'error' in severity list: %s", spl)
		}
		if !strings.Contains(spl, "critical") {
			t.Errorf("expected 'critical' in severity list: %s", spl)
		}
	})

	t.Run("level field excluded from filters", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"level":   "error",
				"service": "api",
			},
		}
		spl := buildSPL(q, 100)
		if !strings.Contains(spl, "service=") {
			t.Errorf("expected service filter in: %s", spl)
		}
	})

	t.Run("raw query passthrough", func(t *testing.T) {
		raw := "search index=main error | stats count by host"
		q := &logsift.Query{RawQuery: raw}
		spl := buildSPL(q, 100)
		if spl != raw {
			t.Errorf("expected raw query passthrough, got: %s", spl)
		}
	})

	t.Run("raw query without search prefix", func(t *testing.T) {
		raw := "index=main error"
		q := &logsift.Query{RawQuery: raw}
		spl := buildSPL(q, 100)
		if !strings.Contains(spl, "search ") {
			t.Errorf("expected 'search' prefix added to raw query: %s", spl)
		}
	})

	t.Run("raw query with pipe prefix", func(t *testing.T) {
		raw := "| inputlookup my_lookup"
		q := &logsift.Query{RawQuery: raw}
		spl := buildSPL(q, 100)
		if spl != raw {
			t.Errorf("expected pipe-prefixed query to pass through: %s", spl)
		}
	})
}

func TestNormalizeResult(t *testing.T) {
	t.Run("full result", func(t *testing.T) {
		result := map[string]any{
			"_time":      "2026-02-27T10:00:00.000+00:00",
			"_raw":       "ERROR: connection refused to db-host",
			"host":       "web-01",
			"sourcetype": "app:logs",
			"level":      "error",
		}

		entry := normalizeResult(result)

		if entry.Timestamp.Year() != 2026 {
			t.Errorf("timestamp year = %d, want 2026", entry.Timestamp.Year())
		}
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
		}
		if entry.Message != "ERROR: connection refused to db-host" {
			t.Errorf("message = %q", entry.Message)
		}
		if entry.Host != "web-01" {
			t.Errorf("host = %q, want %q", entry.Host, "web-01")
		}
		if entry.Service != "app:logs" {
			t.Errorf("service = %q, want %q", entry.Service, "app:logs")
		}
	})

	t.Run("service field preferred over sourcetype", func(t *testing.T) {
		result := map[string]any{
			"_time":      "2026-02-27T10:00:00+00:00",
			"_raw":       "test",
			"service":    "payment-api",
			"sourcetype": "app:logs",
		}

		entry := normalizeResult(result)
		if entry.Service != "payment-api" {
			t.Errorf("service = %q, want %q", entry.Service, "payment-api")
		}
	})

	t.Run("embedded severity detection", func(t *testing.T) {
		result := map[string]any{
			"_time": "2026-02-27T10:00:00+00:00",
			"_raw":  "ERROR something went wrong",
		}

		entry := normalizeResult(result)
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
		}
	})

	t.Run("rfc3339 timestamp", func(t *testing.T) {
		result := map[string]any{
			"_time": "2026-02-27T10:30:00Z",
			"_raw":  "test",
		}

		entry := normalizeResult(result)
		if entry.Timestamp.Hour() != 10 || entry.Timestamp.Minute() != 30 {
			t.Errorf("timestamp = %v, expected 10:30", entry.Timestamp)
		}
	})

	t.Run("missing fields graceful", func(t *testing.T) {
		result := map[string]any{}

		entry := normalizeResult(result)
		if entry.Severity != logsift.SeverityInfo {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityInfo)
		}
		if entry.Timestamp.IsZero() {
			t.Error("expected non-zero default timestamp")
		}
	})
}

func TestSeverityLevelsForSPL(t *testing.T) {
	tests := []struct {
		min    string
		expect int
	}{
		{"CRITICAL", 2},  // critical, fatal
		{"ERROR", 4},     // + error, err
		{"WARN", 6},      // + warn, warning
		{"INFO", 7},      // + info
		{"DEBUG", 8},     // + debug
		{"TRACE", 9},     // + trace
	}

	for _, tt := range tests {
		t.Run(tt.min, func(t *testing.T) {
			got := severityLevelsForSPL(tt.min)
			if len(got) < tt.expect {
				t.Errorf("severityLevelsForSPL(%q) = %v (%d), want at least %d", tt.min, got, len(got), tt.expect)
			}
		})
	}
}

func TestSetAuth(t *testing.T) {
	b := &splunkBackend{}

	t.Run("token with prefix", func(t *testing.T) {
		inst := splunkInstance{token: "Splunk abc123"}
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		b.setAuth(req, inst)
		if req.Header.Get("Authorization") != "Splunk abc123" {
			t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
		}
	})

	t.Run("token without prefix", func(t *testing.T) {
		inst := splunkInstance{token: "abc123"}
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		b.setAuth(req, inst)
		if req.Header.Get("Authorization") != "Splunk abc123" {
			t.Errorf("Authorization = %q, want %q", req.Header.Get("Authorization"), "Splunk abc123")
		}
	})

	t.Run("bearer token", func(t *testing.T) {
		inst := splunkInstance{token: "Bearer jwt-token"}
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		b.setAuth(req, inst)
		if req.Header.Get("Authorization") != "Bearer jwt-token" {
			t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
		}
	})

	t.Run("basic auth", func(t *testing.T) {
		inst := splunkInstance{username: "admin", password: "changeme"}
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		b.setAuth(req, inst)
		user, pass, ok := req.BasicAuth()
		if !ok || user != "admin" || pass != "changeme" {
			t.Errorf("basic auth not set correctly: ok=%v, user=%q, pass=%q", ok, user, pass)
		}
	})
}

func TestRegistered(t *testing.T) {
	backends := logsift.RegisteredBackends()
	found := false
	for _, name := range backends {
		if name == "splunk" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("splunk not found in RegisteredBackends(): %v", backends)
	}
}

func TestAvailableWithURL(t *testing.T) {
	available := logsift.Available(&logsift.Credentials{
		SplunkURL: "https://splunk.example.com:8089",
	})
	found := false
	for _, name := range available {
		if name == "splunk" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("splunk not found in Available() with URL: %v", available)
	}
}
