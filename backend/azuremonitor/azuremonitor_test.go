package azuremonitor

import (
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/monitor/azquery"

	logsift "github.com/fulminate-io/logsift"
)

func TestAvailable(t *testing.T) {
	b := &azureBackend{}

	tests := []struct {
		name   string
		creds  *logsift.Credentials
		expect bool
	}{
		{"nil creds", nil, false},
		{"empty creds", &logsift.Credentials{}, false},
		{"workspace id set", &logsift.Credentials{
			AzureWorkspaceID: "abc-123",
		}, true},
		{"instance with workspace id", &logsift.Credentials{
			AzureInstances: []logsift.AzureMonitorInstanceConfig{
				{Name: "prod", WorkspaceID: "ws-1"},
			},
		}, true},
		{"instance without workspace id", &logsift.Credentials{
			AzureInstances: []logsift.AzureMonitorInstanceConfig{
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
	b := &azureBackend{}

	t.Run("nil creds", func(t *testing.T) {
		got := b.resolveInstances(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("flat fields", func(t *testing.T) {
		creds := &logsift.Credentials{
			AzureTenantID:     "tenant-1",
			AzureClientID:     "client-1",
			AzureClientSecret: "secret-1",
			AzureWorkspaceID:  "ws-1",
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "default" {
			t.Errorf("name = %q, want %q", got[0].name, "default")
		}
		if got[0].tenantID != "tenant-1" {
			t.Errorf("tenantID = %q, want %q", got[0].tenantID, "tenant-1")
		}
		if got[0].workspaceID != "ws-1" {
			t.Errorf("workspaceID = %q, want %q", got[0].workspaceID, "ws-1")
		}
	})

	t.Run("multi-instance preferred", func(t *testing.T) {
		creds := &logsift.Credentials{
			AzureWorkspaceID: "flat-ws",
			AzureInstances: []logsift.AzureMonitorInstanceConfig{
				{Name: "prod", WorkspaceID: "ws-prod"},
				{Name: "staging", WorkspaceID: "ws-staging"},
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

	t.Run("skip instances without workspace id", func(t *testing.T) {
		creds := &logsift.Credentials{
			AzureInstances: []logsift.AzureMonitorInstanceConfig{
				{Name: "no-ws"},
				{Name: "has-ws", WorkspaceID: "ws-1"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "has-ws" {
			t.Errorf("name = %q, want %q", got[0].name, "has-ws")
		}
	})

	t.Run("default name when empty", func(t *testing.T) {
		creds := &logsift.Credentials{
			AzureInstances: []logsift.AzureMonitorInstanceConfig{
				{WorkspaceID: "ws-1"},
			},
		}
		got := b.resolveInstances(creds)
		if len(got) != 1 {
			t.Fatalf("expected 1 instance, got %d", len(got))
		}
		if got[0].name != "azuremonitor" {
			t.Errorf("name = %q, want %q", got[0].name, "azuremonitor")
		}
	})
}

func TestBuildKQL(t *testing.T) {
	t.Run("default source", func(t *testing.T) {
		q := &logsift.Query{}
		kql := buildKQL(q, 100)
		if !strings.Contains(kql, "ContainerLogV2") {
			t.Errorf("expected default source ContainerLogV2 in: %s", kql)
		}
		if !strings.Contains(kql, "take 100") {
			t.Errorf("expected take 100 in: %s", kql)
		}
		if !strings.Contains(kql, "order by TimeGenerated desc") {
			t.Errorf("expected order by in: %s", kql)
		}
	})

	t.Run("custom source", func(t *testing.T) {
		q := &logsift.Query{Source: "Syslog"}
		kql := buildKQL(q, 50)
		if !strings.Contains(kql, "Syslog") {
			t.Errorf("expected Syslog source in: %s", kql)
		}
		if strings.Contains(kql, "ContainerLogV2") {
			t.Errorf("should not contain default source in: %s", kql)
		}
	})

	t.Run("text filter", func(t *testing.T) {
		q := &logsift.Query{TextFilter: "connection refused"}
		kql := buildKQL(q, 100)
		if !strings.Contains(kql, "contains") {
			t.Errorf("expected contains in: %s", kql)
		}
		if !strings.Contains(kql, "connection refused") {
			t.Errorf("expected text filter in: %s", kql)
		}
	})

	t.Run("field filters mapped", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"namespace": "production",
				"pod":       "web-pod-1",
			},
		}
		kql := buildKQL(q, 100)
		if !strings.Contains(kql, "PodNamespace") {
			t.Errorf("expected PodNamespace in: %s", kql)
		}
		if !strings.Contains(kql, "PodName") {
			t.Errorf("expected PodName in: %s", kql)
		}
	})

	t.Run("severity filter", func(t *testing.T) {
		q := &logsift.Query{SeverityMin: "ERROR"}
		kql := buildKQL(q, 100)
		if !strings.Contains(kql, "LogLevel in") {
			t.Errorf("expected LogLevel in clause in: %s", kql)
		}
		if !strings.Contains(kql, "ERROR") {
			t.Errorf("expected ERROR in severity list: %s", kql)
		}
		if !strings.Contains(kql, "CRITICAL") {
			t.Errorf("expected CRITICAL in severity list: %s", kql)
		}
	})

	t.Run("level field excluded from filters", func(t *testing.T) {
		q := &logsift.Query{
			FieldFilters: map[string]string{
				"level":   "error",
				"service": "api",
			},
		}
		kql := buildKQL(q, 100)
		if !strings.Contains(kql, "service") {
			t.Errorf("expected service filter in: %s", kql)
		}
		// LogLevel should NOT appear as a where clause from field filters.
		if strings.Contains(kql, "where LogLevel ==") {
			t.Errorf("LogLevel should not be a field filter in: %s", kql)
		}
	})

	t.Run("raw query passthrough", func(t *testing.T) {
		raw := "ContainerLogV2 | where LogMessage contains 'error' | take 10"
		q := &logsift.Query{RawQuery: raw}
		kql := buildKQL(q, 100)
		if kql != raw {
			t.Errorf("expected raw query passthrough, got: %s", kql)
		}
	})
}

func TestNormalizeRow(t *testing.T) {
	// Helper to build column index from column names.
	makeColIndex := func(names ...string) (map[string]int, []*azquery.Column) {
		idx := make(map[string]int, len(names))
		cols := make([]*azquery.Column, len(names))
		for i, name := range names {
			n := name
			idx[name] = i
			cols[i] = &azquery.Column{Name: &n}
		}
		return idx, cols
	}

	t.Run("full row", func(t *testing.T) {
		colIndex, _ := makeColIndex("TimeGenerated", "LogLevel", "LogMessage", "Computer")
		row := azquery.Row{
			"2026-02-27T10:00:00.123456789Z",
			"ERROR",
			"connection refused",
			"node-01",
		}

		entry := normalizeRow(row, colIndex)

		if entry.Timestamp.Year() != 2026 {
			t.Errorf("timestamp year = %d, want 2026", entry.Timestamp.Year())
		}
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
		}
		if entry.Message != "connection refused" {
			t.Errorf("message = %q, want %q", entry.Message, "connection refused")
		}
		if entry.Host != "node-01" {
			t.Errorf("host = %q, want %q", entry.Host, "node-01")
		}
	})

	t.Run("fallback message field", func(t *testing.T) {
		colIndex, _ := makeColIndex("TimeGenerated", "message")
		row := azquery.Row{
			"2026-02-27T10:00:00Z",
			"hello from message field",
		}

		entry := normalizeRow(row, colIndex)
		if entry.Message != "hello from message field" {
			t.Errorf("message = %q, want %q", entry.Message, "hello from message field")
		}
	})

	t.Run("map LogMessage", func(t *testing.T) {
		colIndex, _ := makeColIndex("TimeGenerated", "LogMessage")
		row := azquery.Row{
			"2026-02-27T10:00:00Z",
			map[string]any{"msg": "structured message"},
		}

		entry := normalizeRow(row, colIndex)
		// The map should be marshaled to JSON since ExtractMessageFromMap may not find "msg".
		if entry.Message == "" {
			t.Error("expected non-empty message from map LogMessage")
		}
	})

	t.Run("timestamp format without nanos", func(t *testing.T) {
		colIndex, _ := makeColIndex("TimeGenerated", "LogMessage")
		row := azquery.Row{
			"2026-02-27T10:00:00Z",
			"test",
		}

		entry := normalizeRow(row, colIndex)
		if entry.Timestamp.Year() != 2026 {
			t.Errorf("timestamp year = %d, want 2026", entry.Timestamp.Year())
		}
	})

	t.Run("embedded severity detection", func(t *testing.T) {
		colIndex, _ := makeColIndex("TimeGenerated", "LogMessage")
		row := azquery.Row{
			"2026-02-27T10:00:00Z",
			"ERROR something went wrong",
		}

		entry := normalizeRow(row, colIndex)
		if entry.Severity != logsift.SeverityError {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityError)
		}
	})

	t.Run("missing columns graceful", func(t *testing.T) {
		colIndex, _ := makeColIndex("SomeOtherColumn")
		row := azquery.Row{"value"}

		entry := normalizeRow(row, colIndex)
		// Should not panic, should have default timestamp and severity.
		if entry.Severity != logsift.SeverityInfo {
			t.Errorf("severity = %q, want %q", entry.Severity, logsift.SeverityInfo)
		}
		if entry.Timestamp.IsZero() {
			t.Error("expected non-zero default timestamp")
		}
	})
}

func TestSeverityLevelsForKQL(t *testing.T) {
	tests := []struct {
		min    string
		expect int
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
			got := severityLevelsForKQL(tt.min)
			if len(got) < tt.expect {
				t.Errorf("severityLevelsForKQL(%q) = %v (%d), want at least %d", tt.min, got, len(got), tt.expect)
			}
		})
	}
}

func TestSearchInstanceRespectsTimes(t *testing.T) {
	// Verify buildKQL handles time ranges properly in the query body.
	now := time.Now().UTC()
	q := &logsift.Query{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	}
	kql := buildKQL(q, 100)
	// The KQL itself doesn't add time filters (time is handled via azquery.Body.Timespan),
	// but it should still have the standard order/take.
	if !strings.Contains(kql, "order by TimeGenerated desc") {
		t.Errorf("expected order clause in: %s", kql)
	}
}

func TestRegistered(t *testing.T) {
	backends := logsift.RegisteredBackends()
	found := false
	for _, name := range backends {
		if name == "azuremonitor" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("azuremonitor not found in RegisteredBackends(): %v", backends)
	}
}

func TestAvailableWithWorkspaceID(t *testing.T) {
	available := logsift.Available(&logsift.Credentials{
		AzureWorkspaceID: "ws-123",
	})
	found := false
	for _, name := range available {
		if name == "azuremonitor" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("azuremonitor not found in Available() with workspace ID: %v", available)
	}
}
