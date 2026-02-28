package sumologic

import (
	"strings"
	"testing"

	logsift "github.com/fulminate-io/logsift"
)

func TestAvailable(t *testing.T) {
	b := &sumoBackend{}

	tests := []struct {
		name   string
		creds  *logsift.Credentials
		expect bool
	}{
		{"nil creds", nil, false},
		{"empty creds", &logsift.Credentials{}, false},
		{"access id only", &logsift.Credentials{
			SumoLogicAccessID: "suXXX",
		}, false},
		{"access id and key only", &logsift.Credentials{
			SumoLogicAccessID:  "suXXX",
			SumoLogicAccessKey: "keyXXX",
		}, false},
		{"all flat fields", &logsift.Credentials{
			SumoLogicAccessID:  "suXXX",
			SumoLogicAccessKey: "keyXXX",
			SumoLogicURL:       "https://api.us2.sumologic.com",
		}, true},
		{"instance with all fields", &logsift.Credentials{
			SumoLogicInstances: []logsift.SumoLogicInstanceConfig{
				{Name: "prod", AccessID: "suXXX", AccessKey: "keyXXX", URL: "https://api.us2.sumologic.com"},
			},
		}, true},
		{"instance missing url", &logsift.Credentials{
			SumoLogicInstances: []logsift.SumoLogicInstanceConfig{
				{Name: "empty", AccessID: "suXXX", AccessKey: "keyXXX"},
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
	b := &sumoBackend{}

	t.Run("nil creds", func(t *testing.T) {
		got := b.resolveInstances(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("flat fields", func(t *testing.T) {
		creds := &logsift.Credentials{
			SumoLogicAccessID:  "suABC",
			SumoLogicAccessKey: "keyABC",
			SumoLogicURL:       "https://api.us2.sumologic.com",
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "default" {
			t.Errorf("name = %q, want %q", got[0].name, "default")
		}
		if got[0].accessID != "suABC" {
			t.Errorf("accessID = %q, want %q", got[0].accessID, "suABC")
		}
		if got[0].baseURL != "https://api.us2.sumologic.com" {
			t.Errorf("baseURL = %q", got[0].baseURL)
		}
	})

	t.Run("trailing slash trimmed", func(t *testing.T) {
		creds := &logsift.Credentials{
			SumoLogicAccessID:  "suABC",
			SumoLogicAccessKey: "keyABC",
			SumoLogicURL:       "https://api.us2.sumologic.com/",
		}
		got := b.resolveInstances(creds)
		if got[0].baseURL != "https://api.us2.sumologic.com" {
			t.Errorf("baseURL = %q, trailing slash not trimmed", got[0].baseURL)
		}
	})

	t.Run("multi-instance preferred", func(t *testing.T) {
		creds := &logsift.Credentials{
			SumoLogicAccessID:  "flat",
			SumoLogicAccessKey: "flat",
			SumoLogicURL:       "https://api.sumologic.com",
			SumoLogicInstances: []logsift.SumoLogicInstanceConfig{
				{Name: "us2", AccessID: "su1", AccessKey: "key1", URL: "https://api.us2.sumologic.com"},
				{Name: "eu", AccessID: "su2", AccessKey: "key2", URL: "https://api.eu.sumologic.com"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 2 {
			t.Fatalf("expected 2 instances, got %d", len(got))
		}
		if got[0].name != "us2" || got[1].name != "eu" {
			t.Errorf("unexpected names: %v, %v", got[0].name, got[1].name)
		}
	})

	t.Run("skip invalid instances", func(t *testing.T) {
		creds := &logsift.Credentials{
			SumoLogicInstances: []logsift.SumoLogicInstanceConfig{
				{Name: "no-key", AccessID: "suXXX", URL: "https://api.sumologic.com"},
				{Name: "valid", AccessID: "suXXX", AccessKey: "keyXXX", URL: "https://api.us2.sumologic.com"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "valid" {
			t.Errorf("name = %q, want %q", got[0].name, "valid")
		}
	})

	t.Run("default name when empty", func(t *testing.T) {
		creds := &logsift.Credentials{
			SumoLogicInstances: []logsift.SumoLogicInstanceConfig{
				{AccessID: "suXXX", AccessKey: "keyXXX", URL: "https://api.sumologic.com"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "sumologic" {
			t.Errorf("name = %q, want %q", got[0].name, "sumologic")
		}
	})
}

func TestBuildSumoQuery(t *testing.T) {
	t.Run("default query", func(t *testing.T) {
		q := &logsift.Query{}
		query := buildSumoQuery(q)
		if !strings.Contains(query, "* | json auto") {
			t.Errorf("expected '* | json auto' in: %s", query)
		}
	})

	t.Run("source as source category", func(t *testing.T) {
		q := &logsift.Query{Source: "prod/kubernetes/myapp"}
		query := buildSumoQuery(q)
		if !strings.Contains(query, "_sourceCategory=prod/kubernetes/myapp") {
			t.Errorf("expected _sourceCategory filter in: %s", query)
		}
	})

	t.Run("text filter", func(t *testing.T) {
		q := &logsift.Query{TextFilter: "connection refused"}
		query := buildSumoQuery(q)
		if !strings.Contains(query, "connection refused") {
			t.Errorf("expected text filter in: %s", query)
		}
	})

	t.Run("field filters mapped", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"namespace": "production",
				"host":      "web-01",
			},
		}
		query := buildSumoQuery(q)
		if !strings.Contains(query, "namespace") {
			t.Errorf("expected namespace filter in: %s", query)
		}
		if !strings.Contains(query, "_sourceHost=web-01") {
			t.Errorf("expected _sourceHost filter in: %s", query)
		}
	})

	t.Run("severity filter", func(t *testing.T) {
		q := &logsift.Query{SeverityMin: "ERROR"}
		query := buildSumoQuery(q)
		if !strings.Contains(query, "where") {
			t.Errorf("expected where clause in: %s", query)
		}
		if !strings.Contains(query, "error") {
			t.Errorf("expected 'error' in severity: %s", query)
		}
		if !strings.Contains(query, "critical") {
			t.Errorf("expected 'critical' in severity: %s", query)
		}
	})

	t.Run("level field excluded from filters", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"level":   "error",
				"service": "api",
			},
		}
		query := buildSumoQuery(q)
		if !strings.Contains(query, "_sourceCategory") {
			t.Errorf("expected _sourceCategory (mapped from service) in: %s", query)
		}
	})

	t.Run("raw query passthrough", func(t *testing.T) {
		raw := "_sourceCategory=prod/* | json auto | where level=\"error\""
		q := &logsift.Query{RawQuery: raw}
		query := buildSumoQuery(q)
		if query != raw {
			t.Errorf("expected raw query passthrough, got: %s", query)
		}
	})
}

func TestNormalizeMessage(t *testing.T) {
	t.Run("full message", func(t *testing.T) {
		msg := map[string]string{
			"_messagetime":     "1772139600000",
			"_raw":             "ERROR: connection refused to db",
			"_sourceHost":      "web-01",
			"_sourceCategory":  "prod/kubernetes/myapp",
			"level":            "error",
		}

		entry := normalizeMessage(msg)

		if entry.Timestamp.Year() != 2026 {
			t.Errorf("timestamp year = %d, want 2026", entry.Timestamp.Year())
		}
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
		}
		if entry.Message != "ERROR: connection refused to db" {
			t.Errorf("message = %q", entry.Message)
		}
		if entry.Host != "web-01" {
			t.Errorf("host = %q, want %q", entry.Host, "web-01")
		}
		if entry.Service != "prod/kubernetes/myapp" {
			t.Errorf("service = %q, want %q", entry.Service, "prod/kubernetes/myapp")
		}
	})

	t.Run("_loglevel preferred", func(t *testing.T) {
		msg := map[string]string{
			"_messagetime": "1772139600000",
			"_raw":         "test",
			"_loglevel":    "warn",
		}

		entry := normalizeMessage(msg)
		if entry.Severity != logsift.SeverityWarn {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityWarn)
		}
	})

	t.Run("embedded severity detection", func(t *testing.T) {
		msg := map[string]string{
			"_messagetime": "1772139600000",
			"_raw":         "ERROR something went wrong",
		}

		entry := normalizeMessage(msg)
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
		}
	})

	t.Run("missing fields graceful", func(t *testing.T) {
		msg := map[string]string{}

		entry := normalizeMessage(msg)
		if entry.Severity != logsift.SeverityInfo {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityInfo)
		}
		if entry.Timestamp.IsZero() {
			t.Error("expected non-zero default timestamp")
		}
	})
}

func TestSeverityLevelsForSumo(t *testing.T) {
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
			got := severityLevelsForSumo(tt.min)
			if len(got) < tt.expect {
				t.Errorf("severityLevelsForSumo(%q) = %v (%d), want at least %d", tt.min, got, len(got), tt.expect)
			}
		})
	}
}

func TestRegistered(t *testing.T) {
	backends := logsift.RegisteredBackends()
	found := false
	for _, name := range backends {
		if name == "sumologic" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("sumologic not found in RegisteredBackends(): %v", backends)
	}
}

func TestAvailableWithCreds(t *testing.T) {
	available := logsift.Available(&logsift.Credentials{
		SumoLogicAccessID:  "suXXX",
		SumoLogicAccessKey: "keyXXX",
		SumoLogicURL:       "https://api.us2.sumologic.com",
	})
	found := false
	for _, name := range available {
		if name == "sumologic" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("sumologic not found in Available() with creds: %v", available)
	}
}
