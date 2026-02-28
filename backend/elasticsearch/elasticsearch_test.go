package elasticsearch

import (
	"encoding/json"
	"strings"
	"testing"

	logsift "github.com/fulminate-io/logsift"
	"github.com/opensearch-project/opensearch-go/v4/opensearchapi"
)

func TestAvailable(t *testing.T) {
	b := &esBackend{}

	tests := []struct {
		name   string
		creds  *logsift.Credentials
		expect bool
	}{
		{"nil creds", nil, false},
		{"empty creds", &logsift.Credentials{}, false},
		{"addresses set", &logsift.Credentials{
			ElasticsearchAddresses: []string{"https://localhost:9200"},
		}, true},
		{"cloud id set", &logsift.Credentials{
			ElasticsearchCloudID: "my-deploy:...",
		}, true},
		{"instance with addresses", &logsift.Credentials{
			ElasticsearchInstances: []logsift.ElasticsearchInstanceConfig{
				{Name: "prod", Addresses: []string{"https://prod:9200"}},
			},
		}, true},
		{"instance without addresses or cloud id", &logsift.Credentials{
			ElasticsearchInstances: []logsift.ElasticsearchInstanceConfig{
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
	b := &esBackend{}

	t.Run("nil creds", func(t *testing.T) {
		got := b.resolveInstances(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("flat fields", func(t *testing.T) {
		creds := &logsift.Credentials{
			ElasticsearchAddresses: []string{"https://localhost:9200"},
			ElasticsearchUsername:  "elastic",
			ElasticsearchPassword:  "changeme",
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "default" {
			t.Errorf("name = %q, want %q", got[0].name, "default")
		}
		if got[0].username != "elastic" {
			t.Errorf("username = %q, want %q", got[0].username, "elastic")
		}
	})

	t.Run("multi-instance preferred", func(t *testing.T) {
		creds := &logsift.Credentials{
			ElasticsearchAddresses: []string{"https://flat:9200"},
			ElasticsearchInstances: []logsift.ElasticsearchInstanceConfig{
				{Name: "prod", Addresses: []string{"https://prod:9200"}},
				{Name: "staging", Addresses: []string{"https://staging:9200"}},
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

	t.Run("skip instances without addresses", func(t *testing.T) {
		creds := &logsift.Credentials{
			ElasticsearchInstances: []logsift.ElasticsearchInstanceConfig{
				{Name: "no-addr"},
				{Name: "has-addr", Addresses: []string{"https://valid:9200"}},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "has-addr" {
			t.Errorf("name = %q, want %q", got[0].name, "has-addr")
		}
	})
}

func TestBuildQueryDSL(t *testing.T) {
	t.Run("match_all when empty", func(t *testing.T) {
		q := &logsift.Query{}
		dsl := buildQueryDSL(q, 100)
		b, _ := json.Marshal(dsl)
		s := string(b)
		if !strings.Contains(s, "match_all") {
			t.Errorf("expected match_all in: %s", s)
		}
		if !strings.Contains(s, `"size":100`) {
			t.Errorf("expected size:100 in: %s", s)
		}
	})

	t.Run("text filter as must match", func(t *testing.T) {
		q := &logsift.Query{TextFilter: "connection refused"}
		dsl := buildQueryDSL(q, 100)
		b, _ := json.Marshal(dsl)
		s := string(b)
		if !strings.Contains(s, "connection refused") {
			t.Errorf("expected text filter in: %s", s)
		}
		if !strings.Contains(s, "must") {
			t.Errorf("expected must clause in: %s", s)
		}
	})

	t.Run("field filters mapped", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"namespace": "production",
				"service":   "payment-api",
			},
		}
		dsl := buildQueryDSL(q, 100)
		b, _ := json.Marshal(dsl)
		s := string(b)
		if !strings.Contains(s, "kubernetes.namespace") {
			t.Errorf("expected kubernetes.namespace in: %s", s)
		}
		if !strings.Contains(s, "service.name") {
			t.Errorf("expected service.name in: %s", s)
		}
	})

	t.Run("severity filter as terms", func(t *testing.T) {
		q := &logsift.Query{SeverityMin: "ERROR"}
		dsl := buildQueryDSL(q, 100)
		b, _ := json.Marshal(dsl)
		s := string(b)
		if !strings.Contains(s, "log.level") {
			t.Errorf("expected log.level in: %s", s)
		}
		if !strings.Contains(s, "error") {
			t.Errorf("expected 'error' in severity terms: %s", s)
		}
		if !strings.Contains(s, "critical") {
			t.Errorf("expected 'critical' in severity terms: %s", s)
		}
	})

	t.Run("raw query passthrough JSON", func(t *testing.T) {
		raw := `{"size":50,"query":{"match_all":{}}}`
		q := &logsift.Query{RawQuery: raw}
		dsl := buildQueryDSL(q, 100)
		b, _ := json.Marshal(dsl)
		s := string(b)
		if !strings.Contains(s, "match_all") {
			t.Errorf("expected raw query passthrough in: %s", s)
		}
	})

	t.Run("raw query passthrough non-JSON", func(t *testing.T) {
		q := &logsift.Query{RawQuery: "service:web AND status:error"}
		dsl := buildQueryDSL(q, 100)
		b, _ := json.Marshal(dsl)
		s := string(b)
		if !strings.Contains(s, "query_string") {
			t.Errorf("expected query_string fallback in: %s", s)
		}
	})

	t.Run("level field excluded from filters", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"level":   "error",
				"service": "api",
			},
		}
		dsl := buildQueryDSL(q, 100)
		b, _ := json.Marshal(dsl)
		s := string(b)
		if !strings.Contains(s, "service.name") {
			t.Errorf("expected service.name in: %s", s)
		}
		// log.level should not appear as a term filter (it's the canonical level mapping).
		if strings.Contains(s, `"term":{"log.level"`) {
			t.Errorf("log.level should not be a term filter in: %s", s)
		}
	})
}

func TestNormalizeHit(t *testing.T) {
	t.Run("full ECS document", func(t *testing.T) {
		source := map[string]any{
			"@timestamp": "2026-02-27T10:00:00.000Z",
			"message":    "connection refused",
			"log":        map[string]any{"level": "error"},
			"service":    map[string]any{"name": "payment-api"},
			"host":       map[string]any{"name": "node-01"},
		}
		b, _ := json.Marshal(source)
		hit := opensearchapi.SearchHit{Source: b}
		entry := normalizeHit(hit)

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

	t.Run("flat fields", func(t *testing.T) {
		source := map[string]any{
			"@timestamp": "2026-02-27T10:00:00Z",
			"message":    "hello",
			"level":      "warn",
			"service":    "web-api",
			"host":       "host-1",
		}
		b, _ := json.Marshal(source)
		hit := opensearchapi.SearchHit{Source: b}
		entry := normalizeHit(hit)

		if entry.Severity != logsift.SeverityWarn {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityWarn)
		}
		if entry.Service != "web-api" {
			t.Errorf("service = %q, want %q", entry.Service, "web-api")
		}
	})

	t.Run("embedded severity detection", func(t *testing.T) {
		source := map[string]any{
			"@timestamp": "2026-02-27T10:00:00Z",
			"message":    "ERROR something went wrong",
		}
		b, _ := json.Marshal(source)
		hit := opensearchapi.SearchHit{Source: b}
		entry := normalizeHit(hit)

		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
		}
	})
}

func TestGetNestedString(t *testing.T) {
	m := map[string]any{
		"service": map[string]any{
			"name": "payment-api",
		},
		"host": "direct-host",
		"log": map[string]any{
			"level": "error",
		},
	}

	tests := []struct {
		key    string
		expect string
	}{
		{"host", "direct-host"},
		{"service.name", "payment-api"},
		{"log.level", "error"},
		{"nonexistent", ""},
		{"service.nonexistent", ""},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := getNestedString(m, tt.key)
			if got != tt.expect {
				t.Errorf("getNestedString(%q) = %q, want %q", tt.key, got, tt.expect)
			}
		})
	}
}

func TestSeverityLevelsForES(t *testing.T) {
	tests := []struct {
		min    string
		expect int
	}{
		{"CRITICAL", 2}, // critical, fatal
		{"ERROR", 3},    // + error
		{"WARN", 5},     // + warn, warning
		{"INFO", 6},     // + info
		{"DEBUG", 7},    // + debug
		{"TRACE", 8},    // + trace
	}

	for _, tt := range tests {
		t.Run(tt.min, func(t *testing.T) {
			got := severityLevelsForES(tt.min)
			if len(got) < tt.expect {
				t.Errorf("severityLevelsForES(%q) = %v (%d), want at least %d", tt.min, got, len(got), tt.expect)
			}
		})
	}
}

func TestRegistered(t *testing.T) {
	backends := logsift.RegisteredBackends()
	found := false
	for _, name := range backends {
		if name == "elasticsearch" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("elasticsearch not found in RegisteredBackends(): %v", backends)
	}
}

func TestAvailableWithAddresses(t *testing.T) {
	available := logsift.Available(&logsift.Credentials{
		ElasticsearchAddresses: []string{"https://localhost:9200"},
	})
	found := false
	for _, name := range available {
		if name == "elasticsearch" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("elasticsearch not found in Available() with addresses: %v", available)
	}
}
