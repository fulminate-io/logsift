package newrelic

import (
	"strings"
	"testing"
	"time"

	logsift "github.com/fulminate-io/logsift"
)

func TestAvailable(t *testing.T) {
	b := &nrBackend{}

	tests := []struct {
		name   string
		creds  *logsift.Credentials
		expect bool
	}{
		{"nil creds", nil, false},
		{"empty creds", &logsift.Credentials{}, false},
		{"api key only", &logsift.Credentials{
			NewRelicAPIKey: "NRAK-123",
		}, false},
		{"account id only", &logsift.Credentials{
			NewRelicAccountID: 123,
		}, false},
		{"api key and account id", &logsift.Credentials{
			NewRelicAPIKey:    "NRAK-123",
			NewRelicAccountID: 123,
		}, true},
		{"instance with both", &logsift.Credentials{
			NewRelicInstances: []logsift.NewRelicInstanceConfig{
				{Name: "prod", APIKey: "NRAK-123", AccountID: 123},
			},
		}, true},
		{"instance without api key", &logsift.Credentials{
			NewRelicInstances: []logsift.NewRelicInstanceConfig{
				{Name: "empty", AccountID: 123},
			},
		}, false},
		{"instance without account id", &logsift.Credentials{
			NewRelicInstances: []logsift.NewRelicInstanceConfig{
				{Name: "empty", APIKey: "NRAK-123"},
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
	b := &nrBackend{}

	t.Run("nil creds", func(t *testing.T) {
		got := b.resolveInstances(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("flat fields", func(t *testing.T) {
		creds := &logsift.Credentials{
			NewRelicAPIKey:    "NRAK-abc",
			NewRelicAccountID: 12345,
			NewRelicRegion:    "US",
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "default" {
			t.Errorf("name = %q, want %q", got[0].name, "default")
		}
		if got[0].apiKey != "NRAK-abc" {
			t.Errorf("apiKey = %q, want %q", got[0].apiKey, "NRAK-abc")
		}
		if got[0].accountID != 12345 {
			t.Errorf("accountID = %d, want %d", got[0].accountID, 12345)
		}
		if got[0].endpoint != nerdGraphUS {
			t.Errorf("endpoint = %q, want %q", got[0].endpoint, nerdGraphUS)
		}
	})

	t.Run("eu region", func(t *testing.T) {
		creds := &logsift.Credentials{
			NewRelicAPIKey:    "NRAK-abc",
			NewRelicAccountID: 12345,
			NewRelicRegion:    "EU",
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].endpoint != nerdGraphEU {
			t.Errorf("endpoint = %q, want %q", got[0].endpoint, nerdGraphEU)
		}
	})

	t.Run("multi-instance preferred", func(t *testing.T) {
		creds := &logsift.Credentials{
			NewRelicAPIKey:    "NRAK-flat",
			NewRelicAccountID: 1,
			NewRelicInstances: []logsift.NewRelicInstanceConfig{
				{Name: "prod", APIKey: "NRAK-prod", AccountID: 100},
				{Name: "staging", APIKey: "NRAK-staging", AccountID: 200},
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

	t.Run("skip invalid instances", func(t *testing.T) {
		creds := &logsift.Credentials{
			NewRelicInstances: []logsift.NewRelicInstanceConfig{
				{Name: "no-key", AccountID: 123},
				{Name: "no-account", APIKey: "NRAK-123"},
				{Name: "valid", APIKey: "NRAK-valid", AccountID: 456},
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
			NewRelicInstances: []logsift.NewRelicInstanceConfig{
				{APIKey: "NRAK-123", AccountID: 123},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "newrelic" {
			t.Errorf("name = %q, want %q", got[0].name, "newrelic")
		}
	})
}

func TestRegionEndpoint(t *testing.T) {
	tests := []struct {
		region string
		expect string
	}{
		{"", nerdGraphUS},
		{"US", nerdGraphUS},
		{"us", nerdGraphUS},
		{"EU", nerdGraphEU},
		{"eu", nerdGraphEU},
	}

	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			got := regionEndpoint(tt.region)
			if got != tt.expect {
				t.Errorf("regionEndpoint(%q) = %q, want %q", tt.region, got, tt.expect)
			}
		})
	}
}

func TestBuildNRQL(t *testing.T) {
	t.Run("default query", func(t *testing.T) {
		q := &logsift.Query{}
		nrql := buildNRQL(q, 100)
		if !strings.Contains(nrql, "SELECT * FROM Log") {
			t.Errorf("expected SELECT * FROM Log in: %s", nrql)
		}
		if !strings.Contains(nrql, "LIMIT 100") {
			t.Errorf("expected LIMIT 100 in: %s", nrql)
		}
		if !strings.Contains(nrql, "ORDER BY timestamp DESC") {
			t.Errorf("expected ORDER BY in: %s", nrql)
		}
		if !strings.Contains(nrql, "SINCE 1 hour ago") {
			t.Errorf("expected default SINCE in: %s", nrql)
		}
	})

	t.Run("text filter", func(t *testing.T) {
		q := &logsift.Query{TextFilter: "connection refused"}
		nrql := buildNRQL(q, 100)
		if !strings.Contains(nrql, "message LIKE") {
			t.Errorf("expected LIKE in: %s", nrql)
		}
		if !strings.Contains(nrql, "connection refused") {
			t.Errorf("expected text filter in: %s", nrql)
		}
	})

	t.Run("source as logtype", func(t *testing.T) {
		q := &logsift.Query{Source: "nginx"}
		nrql := buildNRQL(q, 100)
		if !strings.Contains(nrql, "logtype = 'nginx'") {
			t.Errorf("expected logtype filter in: %s", nrql)
		}
	})

	t.Run("field filters mapped", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"namespace": "production",
				"service":   "payment-api",
			},
		}
		nrql := buildNRQL(q, 100)
		if !strings.Contains(nrql, "kubernetes.namespace_name") {
			t.Errorf("expected kubernetes.namespace_name in: %s", nrql)
		}
		if !strings.Contains(nrql, "service.name") {
			t.Errorf("expected service.name in: %s", nrql)
		}
	})

	t.Run("severity filter", func(t *testing.T) {
		q := &logsift.Query{SeverityMin: "ERROR"}
		nrql := buildNRQL(q, 100)
		if !strings.Contains(nrql, "level IN") {
			t.Errorf("expected level IN in: %s", nrql)
		}
		if !strings.Contains(nrql, "ERROR") {
			t.Errorf("expected ERROR in severity list: %s", nrql)
		}
		if !strings.Contains(nrql, "CRITICAL") {
			t.Errorf("expected CRITICAL in severity list: %s", nrql)
		}
	})

	t.Run("level field excluded from filters", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"level":   "error",
				"service": "api",
			},
		}
		nrql := buildNRQL(q, 100)
		if !strings.Contains(nrql, "service.name") {
			t.Errorf("expected service.name in: %s", nrql)
		}
	})

	t.Run("time range", func(t *testing.T) {
		q := &logsift.Query{
			StartTime: time.Date(2026, 2, 27, 10, 0, 0, 0, time.UTC),
			EndTime:   time.Date(2026, 2, 27, 11, 0, 0, 0, time.UTC),
		}
		nrql := buildNRQL(q, 100)
		if !strings.Contains(nrql, "SINCE") {
			t.Errorf("expected SINCE in: %s", nrql)
		}
		if !strings.Contains(nrql, "UNTIL") {
			t.Errorf("expected UNTIL in: %s", nrql)
		}
		// Should not contain the default "SINCE 1 hour ago".
		if strings.Contains(nrql, "SINCE 1 hour ago") {
			t.Errorf("should not have default time range when explicit times set: %s", nrql)
		}
	})

	t.Run("raw query passthrough", func(t *testing.T) {
		raw := "SELECT * FROM Log WHERE level = 'ERROR' SINCE 1 hour ago LIMIT 10"
		q := &logsift.Query{RawQuery: raw}
		nrql := buildNRQL(q, 100)
		if nrql != raw {
			t.Errorf("expected raw query passthrough, got: %s", nrql)
		}
	})

	t.Run("limit capped at 5000", func(t *testing.T) {
		q := &logsift.Query{}
		nrql := buildNRQL(q, 10000)
		if !strings.Contains(nrql, "LIMIT 5000") {
			t.Errorf("expected LIMIT 5000 (capped) in: %s", nrql)
		}
	})
}

func TestNormalizeResult(t *testing.T) {
	t.Run("full result", func(t *testing.T) {
		result := map[string]any{
			"timestamp":    float64(1772139600000), // 2026-02-27T10:00:00Z in ms
			"message":      "connection refused",
			"level":        "ERROR",
			"hostname":     "web-01",
			"service.name": "payment-api",
		}

		entry := normalizeResult(result)

		if entry.Timestamp.Year() != 2026 {
			t.Errorf("timestamp year = %d, want 2026", entry.Timestamp.Year())
		}
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
		}
		if entry.Message != "connection refused" {
			t.Errorf("message = %q, want %q", entry.Message, "connection refused")
		}
		if entry.Host != "web-01" {
			t.Errorf("host = %q, want %q", entry.Host, "web-01")
		}
		if entry.Service != "payment-api" {
			t.Errorf("service = %q, want %q", entry.Service, "payment-api")
		}
	})

	t.Run("severity field fallback", func(t *testing.T) {
		result := map[string]any{
			"timestamp": float64(1772139600000),
			"message":   "test",
			"severity":  "warning",
		}

		entry := normalizeResult(result)
		if entry.Severity != logsift.SeverityWarn {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityWarn)
		}
	})

	t.Run("entity.name service fallback", func(t *testing.T) {
		result := map[string]any{
			"timestamp":   float64(1772139600000),
			"message":     "test",
			"entity.name": "my-service",
		}

		entry := normalizeResult(result)
		if entry.Service != "my-service" {
			t.Errorf("service = %q, want %q", entry.Service, "my-service")
		}
	})

	t.Run("embedded severity detection", func(t *testing.T) {
		result := map[string]any{
			"timestamp": float64(1772139600000),
			"message":   "ERROR something went wrong",
		}

		entry := normalizeResult(result)
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
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

func TestExtractResults(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		data := map[string]any{
			"actor": map[string]any{
				"account": map[string]any{
					"nrql": map[string]any{
						"results": []any{
							map[string]any{"message": "hello"},
							map[string]any{"message": "world"},
						},
					},
				},
			},
		}

		results, err := extractResults(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 2 {
			t.Errorf("expected 2 results, got %d", len(results))
		}
	})

	t.Run("missing actor", func(t *testing.T) {
		data := map[string]any{}
		_, err := extractResults(data)
		if err == nil {
			t.Error("expected error for missing actor")
		}
	})

	t.Run("empty results", func(t *testing.T) {
		data := map[string]any{
			"actor": map[string]any{
				"account": map[string]any{
					"nrql": map[string]any{
						"results": []any{},
					},
				},
			},
		}

		results, err := extractResults(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 results, got %d", len(results))
		}
	})
}

func TestSeverityLevelsForNRQL(t *testing.T) {
	tests := []struct {
		min    string
		expect int
	}{
		{"CRITICAL", 2},  // CRITICAL, FATAL
		{"ERROR", 3},     // + ERROR
		{"WARN", 5},      // + WARN, WARNING
		{"INFO", 6},      // + INFO
		{"DEBUG", 7},     // + DEBUG
		{"TRACE", 8},     // + TRACE
	}

	for _, tt := range tests {
		t.Run(tt.min, func(t *testing.T) {
			got := severityLevelsForNRQL(tt.min)
			if len(got) < tt.expect {
				t.Errorf("severityLevelsForNRQL(%q) = %v (%d), want at least %d", tt.min, got, len(got), tt.expect)
			}
		})
	}
}

func TestEscapeNRQL(t *testing.T) {
	if escapeNRQL("hello") != "hello" {
		t.Error("should not modify string without quotes")
	}
	if escapeNRQL("it's") != "it\\'s" {
		t.Errorf("escapeNRQL = %q", escapeNRQL("it's"))
	}
}

func TestRegistered(t *testing.T) {
	backends := logsift.RegisteredBackends()
	found := false
	for _, name := range backends {
		if name == "newrelic" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("newrelic not found in RegisteredBackends(): %v", backends)
	}
}

func TestAvailableWithCreds(t *testing.T) {
	available := logsift.Available(&logsift.Credentials{
		NewRelicAPIKey:    "NRAK-test",
		NewRelicAccountID: 12345,
	})
	found := false
	for _, name := range available {
		if name == "newrelic" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("newrelic not found in Available() with creds: %v", available)
	}
}
