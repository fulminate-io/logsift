package loki

import (
	"testing"

	logsift "github.com/fulminate-io/logsift"
)

func TestBuildLogQL(t *testing.T) {
	tests := []struct {
		name string
		q    *logsift.Query
		want string
	}{
		{
			name: "source only",
			q:    &logsift.Query{Source: "my-namespace"},
			want: `{namespace="my-namespace"}`,
		},
		{
			name: "source with text filter",
			q:    &logsift.Query{Source: "my-ns", TextFilter: "error"},
			want: `{namespace="my-ns"} |= "error"`,
		},
		{
			name: "source with raw query",
			q:    &logsift.Query{Source: "my-ns", RawQuery: `| json | level = "error"`},
			want: `{namespace="my-ns"} | json | level = "error"`,
		},
		{
			name: "source with text filter and raw query",
			q:    &logsift.Query{Source: "my-ns", TextFilter: "timeout", RawQuery: "| json"},
			want: `{namespace="my-ns"} |= "timeout" | json`,
		},
		{
			name: "no source — fallback selector",
			q:    &logsift.Query{},
			want: `{namespace=~".+"}`,
		},
		{
			name: "field filter container",
			q: &logsift.Query{
				Source:       "my-ns",
				FieldFilters: map[string]string{"container": "api-server"},
			},
			want: `{container="api-server", namespace="my-ns"}`,
		},
		{
			name: "field filter pod",
			q: &logsift.Query{
				Source:       "my-ns",
				FieldFilters: map[string]string{"pod": "api-abc123"},
			},
			want: `{namespace="my-ns", pod="api-abc123"}`,
		},
		{
			name: "field filter level is skipped",
			q: &logsift.Query{
				Source:       "my-ns",
				FieldFilters: map[string]string{"level": "error"},
			},
			want: `{namespace="my-ns"}`,
		},
		{
			name: "multiple field filters sorted deterministically",
			q: &logsift.Query{
				Source:       "prod",
				FieldFilters: map[string]string{"container": "web", "pod": "web-abc"},
			},
			want: `{container="web", namespace="prod", pod="web-abc"}`,
		},
		{
			name: "special characters in source are Go-quoted",
			q:    &logsift.Query{Source: `my "namespace"`},
			want: `{namespace="my \"namespace\""}`,
		},
		{
			name: "special characters in text filter are Go-quoted",
			q:    &logsift.Query{Source: "ns", TextFilter: `say "hello"`},
			want: `{namespace="ns"} |= "say \"hello\""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildLogQL(tt.q)
			if got != tt.want {
				t.Errorf("buildLogQL():\n  got:  %s\n  want: %s", got, tt.want)
			}
		})
	}
}

func TestParseLogLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMsg string
		wantSev string
	}{
		{
			name:    "plain JSON with level and msg",
			input:   `{"level":"error","ts":"2026-01-01T00:00:00Z","msg":"Operation failed"}`,
			wantMsg: "Operation failed",
			wantSev: logsift.SeverityError,
		},
		{
			name:    "structlog JSON with event field",
			input:   `{"event": "Request validation error", "level": "warning", "lineno": 42}`,
			wantMsg: "Request validation error",
			wantSev: logsift.SeverityWarn,
		},
		{
			name:    "INFO prefix with logger and JSON",
			input:   `INFO  [platform_api] {"event": "Starting request", "level": "info"}`,
			wantMsg: "Starting request",
			wantSev: logsift.SeverityInfo,
		},
		{
			name:    "WARN prefix with logger and JSON",
			input:   `WARN  [mylogger] {"event": "slow query", "level": "warning"}`,
			wantMsg: "slow query",
			wantSev: logsift.SeverityWarn,
		},
		{
			name:    "severity prefix but not JSON after logger",
			input:   `ERROR [mylogger] something went wrong`,
			wantMsg: `ERROR [mylogger] something went wrong`,
			wantSev: logsift.SeverityError,
		},
		{
			name:    "plain text with embedded severity",
			input:   `2026-01-01 Connection timeout after 3200ms`,
			wantMsg: `2026-01-01 Connection timeout after 3200ms`,
			wantSev: logsift.SeverityInfo,
		},
		{
			name:    "plain text with error keyword",
			input:   `failed to connect: connection refused`,
			wantMsg: `failed to connect: connection refused`,
			wantSev: logsift.SeverityInfo, // keyword uplift happens in reducer, not parser
		},
		{
			name:    "JSON without standard message field falls back to full JSON",
			input:   `{"annotations":{"k8s":"v1"},"kind":"Event"}`,
			wantMsg: `{"annotations":{"k8s":"v1"},"kind":"Event"}`,
			wantSev: logsift.SeverityInfo,
		},
		{
			name:    "empty line",
			input:   "",
			wantMsg: "",
			wantSev: logsift.SeverityInfo,
		},
		{
			name:    "plain JSON with severity field",
			input:   `{"severity":"CRITICAL","message":"out of memory"}`,
			wantMsg: "out of memory",
			wantSev: logsift.SeverityCritical,
		},
		{
			name:    "JSON with lvl field",
			input:   `{"lvl":"warn","msg":"retry attempt 3"}`,
			wantMsg: "retry attempt 3",
			wantSev: logsift.SeverityWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMsg, gotSev := parseLogLine(tt.input)
			if tt.wantMsg != "" && gotMsg != tt.wantMsg {
				t.Errorf("message:\n  got:  %q\n  want: %q", gotMsg, tt.wantMsg)
			}
			if gotSev != tt.wantSev {
				t.Errorf("severity: got %q, want %q", gotSev, tt.wantSev)
			}
		})
	}
}

func TestNormalizeEntry(t *testing.T) {
	t.Run("valid nanosecond timestamp", func(t *testing.T) {
		entry := normalizeEntry(
			map[string]string{"namespace": "prod", "container": "api", "pod": "api-xyz"},
			"1709000000000000000", // 2024-02-27T...
			"hello world",
		)
		if entry.Timestamp.Year() < 2024 {
			t.Errorf("expected valid timestamp, got %v", entry.Timestamp)
		}
		if entry.Service != "api" {
			t.Errorf("service: got %q, want %q", entry.Service, "api")
		}
		if entry.Host != "api-xyz" {
			t.Errorf("host: got %q, want %q", entry.Host, "api-xyz")
		}
		if entry.Message != "hello world" {
			t.Errorf("message: got %q, want %q", entry.Message, "hello world")
		}
	})

	t.Run("invalid timestamp falls back to now", func(t *testing.T) {
		entry := normalizeEntry(
			map[string]string{},
			"not-a-number",
			"test",
		)
		if entry.Timestamp.Year() < 2025 {
			t.Errorf("expected fallback to ~now, got %v", entry.Timestamp)
		}
	})

	t.Run("empty stream labels", func(t *testing.T) {
		entry := normalizeEntry(map[string]string{}, "1709000000000000000", "test")
		if entry.Service != "" {
			t.Errorf("expected empty service, got %q", entry.Service)
		}
		if entry.Host != "" {
			t.Errorf("expected empty host, got %q", entry.Host)
		}
	})

	t.Run("JSON log line is parsed", func(t *testing.T) {
		entry := normalizeEntry(
			map[string]string{"namespace": "prod"},
			"1709000000000000000",
			`{"level":"error","msg":"connection reset"}`,
		)
		if entry.Message != "connection reset" {
			t.Errorf("message: got %q, want %q", entry.Message, "connection reset")
		}
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity: got %q, want %q", entry.Severity, logsift.SeverityError)
		}
	})
}

func TestExtractStreamLabel(t *testing.T) {
	tests := []struct {
		name   string
		stream map[string]string
		keys   []string
		want   string
	}{
		{
			name:   "first key matches",
			stream: map[string]string{"container": "api", "pod": "api-xyz"},
			keys:   []string{"container", "pod"},
			want:   "api",
		},
		{
			name:   "fallback to second key",
			stream: map[string]string{"pod": "api-xyz"},
			keys:   []string{"container", "pod"},
			want:   "api-xyz",
		},
		{
			name:   "no keys match",
			stream: map[string]string{"other": "value"},
			keys:   []string{"container", "pod"},
			want:   "",
		},
		{
			name:   "job label splits on slash",
			stream: map[string]string{"job": "monitoring/prometheus"},
			keys:   []string{"job"},
			want:   "prometheus",
		},
		{
			name:   "job label without slash",
			stream: map[string]string{"job": "prometheus"},
			keys:   []string{"job"},
			want:   "prometheus",
		},
		{
			name:   "empty value is skipped",
			stream: map[string]string{"container": "", "pod": "api-xyz"},
			keys:   []string{"container", "pod"},
			want:   "api-xyz",
		},
		{
			name:   "nil stream",
			stream: nil,
			keys:   []string{"container"},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractStreamLabel(tt.stream, tt.keys...)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveInstances(t *testing.T) {
	b := &lokiBackend{}

	t.Run("nil creds returns nil", func(t *testing.T) {
		got := b.resolveInstances(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("flat fields create default instance", func(t *testing.T) {
		creds := &logsift.Credentials{
			LokiAddress:  "http://loki:3100",
			LokiTenantID: "tenant1",
			LokiUsername:  "user",
			LokiPassword:  "pass",
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "default" {
			t.Errorf("name: got %q, want %q", got[0].name, "default")
		}
		if got[0].address != "http://loki:3100" {
			t.Errorf("address: got %q", got[0].address)
		}
		if got[0].tenantID != "tenant1" {
			t.Errorf("tenantID: got %q", got[0].tenantID)
		}
	})

	t.Run("trailing slash stripped from address", func(t *testing.T) {
		creds := &logsift.Credentials{LokiAddress: "http://loki:3100/"}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].address != "http://loki:3100" {
			t.Errorf("address not trimmed: got %q", got[0].address)
		}
	})

	t.Run("multi-instance preferred over flat fields", func(t *testing.T) {
		creds := &logsift.Credentials{
			LokiAddress: "http://should-not-use:3100",
			LokiInstances: []logsift.LokiInstanceConfig{
				{Name: "inst1", Address: "http://loki1:3100"},
				{Name: "inst2", Address: "http://loki2:3100"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 2 {
			t.Fatalf("expected 2 instances, got %d", len(got))
		}
		if got[0].name != "inst1" || got[1].name != "inst2" {
			t.Errorf("wrong instances: %v", got)
		}
	})

	t.Run("instances with empty address are skipped", func(t *testing.T) {
		creds := &logsift.Credentials{
			LokiInstances: []logsift.LokiInstanceConfig{
				{Name: "empty", Address: ""},
				{Name: "valid", Address: "http://loki:3100"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "valid" {
			t.Errorf("wrong instance: %q", got[0].name)
		}
	})

	t.Run("all instances empty falls back to flat fields", func(t *testing.T) {
		creds := &logsift.Credentials{
			LokiAddress: "http://fallback:3100",
			LokiInstances: []logsift.LokiInstanceConfig{
				{Name: "empty", Address: ""},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "default" {
			t.Errorf("expected fallback to flat fields, got %q", got[0].name)
		}
	})

	t.Run("no address at all returns nil", func(t *testing.T) {
		creds := &logsift.Credentials{}
		got := b.resolveInstances(creds)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("bearer token passed through", func(t *testing.T) {
		creds := &logsift.Credentials{
			LokiInstances: []logsift.LokiInstanceConfig{
				{Name: "tok", Address: "http://loki:3100", BearerToken: "my-token"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1, got %d", len(got))
		}
		if got[0].bearerToken != "my-token" {
			t.Errorf("bearerToken: got %q", got[0].bearerToken)
		}
	})
}
