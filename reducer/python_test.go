package reducer

import (
	"strings"
	"testing"
	"time"

	"github.com/fulminate-io/logsift"
)

func TestIsPythonTracebackFragment(t *testing.T) {
	tests := []struct {
		name string
		c    logsift.Cluster
		want bool
	}{
		{"File frame", logsift.Cluster{Template: `  File "/app/server.py", line 42, in handle_request`}, true},
		{"caret underline", logsift.Cluster{Template: "      ^^^^^^^^^^^^^^"}, true},
		{"tilde underline", logsift.Cluster{Template: "      ~~~~~~~~~~~~~~"}, true},
		{"raise statement", logsift.Cluster{Template: "    raise ValueError('invalid input')"}, true},
		{"await statement", logsift.Cluster{Template: "    await self.connection.read()"}, true},
		{"return await", logsift.Cluster{Template: "    return await handler(request)"}, true},
		{"httpx.ReadTimeout", logsift.Cluster{Template: "httpx.ReadTimeout: timed out"}, true},
		{"httpcore.ReadTimeout", logsift.Cluster{Template: "httpcore.ReadTimeout"}, true},
		{"builtins.ValueError", logsift.Cluster{Examples: []string{"builtins.ValueError: invalid literal"}}, true},
		{"exception chain", logsift.Cluster{Template: "The above exception was the direct cause of the following exception:"}, true},
		{"during handling", logsift.Cluster{Template: "During handling of the above exception, another exception occurred:"}, true},
		{"context manager", logsift.Cluster{Template: "    with map_httpcore_exceptions():"}, true},
		{"self method call", logsift.Cluster{Template: "    self.gen.throw(value)"}, true},
		{"assign await", logsift.Cluster{Template: "    response = await transport.handle_async_request(request)"}, true},
		{"normal log", logsift.Cluster{Template: "connection timeout after 3200ms"}, false},
		{"normal error", logsift.Cluster{Template: "failed to process request: context deadline exceeded"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPythonTracebackFragment(&tt.c); got != tt.want {
				t.Errorf("isPythonTracebackFragment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPythonTracebackConsolidator(t *testing.T) {
	c := &pythonTracebackConsolidator{}
	now := time.Now()

	t.Run("merges traceback fragments into single cluster", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "normal error log", Severity: logsift.SeverityError, Count: 5, FirstSeen: now, LastSeen: now.Add(10 * time.Second)},
			{Template: "Traceback (most recent call last):", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now},
			{Template: `  File "/app/server.py", line 42, in handle`, Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now.Add(100 * time.Millisecond)},
			{Template: `  File "/app/client.py", line 99, in fetch`, Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now.Add(200 * time.Millisecond)},
			{Template: "    await self.connection.read()", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now.Add(300 * time.Millisecond)},
			{Template: "      ^^^^^^^^^^^^^^", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now.Add(400 * time.Millisecond)},
			{Template: "httpx.ReadTimeout: timed out", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now.Add(500 * time.Millisecond)},
		}

		result := c.Consolidate(clusters)

		if len(result) != 2 {
			t.Fatalf("expected 2 clusters, got %d", len(result))
		}
		if result[0].Template != "normal error log" {
			t.Errorf("first cluster should be normal, got %q", result[0].Template)
		}

		tb := result[1]
		if tb.Count != 6 {
			t.Errorf("merged count: got %d, want 6", tb.Count)
		}
		if tb.Severity != logsift.SeverityError {
			t.Errorf("merged severity: got %s, want %s", tb.Severity, logsift.SeverityError)
		}
		if !strings.Contains(tb.Template, "Python exception") {
			t.Errorf("merged template should contain 'Python exception', got %q", tb.Template)
		}
	})

	t.Run("fewer than 3 fragments left as-is", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "normal log", Severity: logsift.SeverityInfo, Count: 10, FirstSeen: now, LastSeen: now},
			{Template: `  File "/app/main.py", line 1, in main`, Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now},
			{Template: "    raise SystemExit(0)", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now},
		}

		result := c.Consolidate(clusters)

		if len(result) != 3 {
			t.Fatalf("expected 3 clusters (no consolidation), got %d", len(result))
		}
	})

	t.Run("temporally separated tracebacks stay separate", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "Traceback (most recent call last):", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now},
			{Template: `  File "/app/a.py", line 1`, Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now.Add(100 * time.Millisecond)},
			{Template: "      ^^^^^^^^^^^^^^", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now.Add(200 * time.Millisecond)},
			{Template: "httpx.ReadTimeout: timed out", Severity: logsift.SeverityError, Count: 1, FirstSeen: now, LastSeen: now.Add(300 * time.Millisecond)},
			{Template: "Traceback (most recent call last):", Severity: logsift.SeverityError, Count: 1, FirstSeen: now.Add(30 * time.Second), LastSeen: now.Add(30 * time.Second)},
			{Template: `  File "/app/b.py", line 99`, Severity: logsift.SeverityError, Count: 1, FirstSeen: now.Add(30 * time.Second), LastSeen: now.Add(30100 * time.Millisecond)},
			{Template: "      ~~~~~~~~~~~~~~", Severity: logsift.SeverityError, Count: 1, FirstSeen: now.Add(30 * time.Second), LastSeen: now.Add(30200 * time.Millisecond)},
			{Template: "builtins.ValueError: bad value", Severity: logsift.SeverityError, Count: 1, FirstSeen: now.Add(30 * time.Second), LastSeen: now.Add(30300 * time.Millisecond)},
		}

		result := c.Consolidate(clusters)

		tbCount := 0
		for _, cl := range result {
			if strings.Contains(cl.Template, "Python") {
				tbCount++
			}
		}
		if tbCount != 2 {
			t.Errorf("expected 2 Python traceback clusters, got %d", tbCount)
		}
	})
}
