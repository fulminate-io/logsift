package gcp

import (
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/logging"

	logsift "github.com/fulminate-io/logsift"
)

func TestBuildGCPFilter(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		projectID string
		query     *logsift.Query
		contains  []string
		notContains []string
	}{
		{
			name:      "time range",
			projectID: "my-project",
			query: &logsift.Query{
				StartTime: now.Add(-15 * time.Minute),
				EndTime:   now,
			},
			contains: []string{
				`timestamp >= "2024-06-15T11:45:00Z"`,
				`timestamp <= "2024-06-15T12:00:00Z"`,
			},
		},
		{
			name:      "severity filter",
			projectID: "my-project",
			query: &logsift.Query{
				SeverityMin: logsift.SeverityError,
				StartTime:   now.Add(-15 * time.Minute),
				EndTime:     now,
			},
			contains: []string{"severity >= ERROR"},
		},
		{
			name:      "source short form",
			projectID: "my-project",
			query: &logsift.Query{
				Source:    "stderr",
				StartTime: now.Add(-15 * time.Minute),
				EndTime:   now,
			},
			contains: []string{`logName="projects/my-project/logs/stderr"`},
		},
		{
			name:      "source full form",
			projectID: "my-project",
			query: &logsift.Query{
				Source:    "projects/other/logs/stdout",
				StartTime: now.Add(-15 * time.Minute),
				EndTime:   now,
			},
			contains: []string{`logName="projects/other/logs/stdout"`},
		},
		{
			name:      "text filter",
			projectID: "my-project",
			query: &logsift.Query{
				TextFilter: "connection timeout",
				StartTime:  now.Add(-15 * time.Minute),
				EndTime:    now,
			},
			contains: []string{`"connection timeout"`},
		},
		{
			name:      "field filters",
			projectID: "my-project",
			query: &logsift.Query{
				FieldFilters: map[string]string{"pod": "web-abc123"},
				StartTime:    now.Add(-15 * time.Minute),
				EndTime:      now,
			},
			contains: []string{`resource.labels.pod_name="web-abc123"`},
		},
		{
			name:      "raw query",
			projectID: "my-project",
			query: &logsift.Query{
				RawQuery:  `resource.type="k8s_container"`,
				StartTime: now.Add(-15 * time.Minute),
				EndTime:   now,
			},
			contains: []string{`resource.type="k8s_container"`},
		},
		{
			name:      "combined",
			projectID: "my-project",
			query: &logsift.Query{
				SeverityMin:  logsift.SeverityWarn,
				Source:       "stderr",
				TextFilter:   "error",
				FieldFilters: map[string]string{"service": "api"},
				StartTime:    now.Add(-1 * time.Hour),
				EndTime:      now,
			},
			contains: []string{
				"severity >= WARNING",
				`logName="projects/my-project/logs/stderr"`,
				`"error"`,
				`resource.labels.service_name="api"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildGCPFilter(tt.projectID, tt.query)
			for _, s := range tt.contains {
				if !strings.Contains(got, s) {
					t.Errorf("filter should contain %q, got:\n%s", s, got)
				}
			}
			for _, s := range tt.notContains {
				if strings.Contains(got, s) {
					t.Errorf("filter should NOT contain %q, got:\n%s", s, got)
				}
			}
		})
	}
}

func TestMapGCPSeverity(t *testing.T) {
	tests := []struct {
		input logging.Severity
		want  string
	}{
		{logging.Emergency, logsift.SeverityCritical},
		{logging.Alert, logsift.SeverityCritical},
		{logging.Critical, logsift.SeverityCritical},
		{logging.Error, logsift.SeverityError},
		{logging.Warning, logsift.SeverityWarn},
		{logging.Notice, logsift.SeverityInfo},
		{logging.Info, logsift.SeverityInfo},
		{logging.Debug, logsift.SeverityDebug},
		{logging.Default, logsift.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input.String(), func(t *testing.T) {
			got := mapGCPSeverity(tt.input)
			if got != tt.want {
				t.Errorf("mapGCPSeverity(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMapSeverityToGCP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{logsift.SeverityTrace, "DEBUG"},
		{logsift.SeverityDebug, "DEBUG"},
		{logsift.SeverityInfo, "INFO"},
		{logsift.SeverityWarn, "WARNING"},
		{logsift.SeverityError, "ERROR"},
		{logsift.SeverityCritical, "CRITICAL"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapSeverityToGCP(tt.input)
			if got != tt.want {
				t.Errorf("mapSeverityToGCP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractLogID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"full path", "projects/my-project/logs/stderr", "stderr"},
		{"url encoded", "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity", "cloudaudit.googleapis.com/activity"},
		{"no /logs/ prefix", "some-random-string", "some-random-string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLogID(tt.input)
			if got != tt.want {
				t.Errorf("extractLogID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEscapeGCPValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`clean`, `clean`},
		{`has "quotes"`, `has \"quotes\"`},
		{`has \backslash`, `has \\backslash`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeGCPValue(tt.input)
			if got != tt.want {
				t.Errorf("escapeGCPValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEscapeGCPTextFilter(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"already quoted", `"exact match"`, `"exact match"`},
		{"unquoted wraps", `connection timeout`, `"connection timeout"`},
		{"special chars", `has "quotes" inside`, `"has \"quotes\" inside"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeGCPTextFilter(tt.input)
			if got != tt.want {
				t.Errorf("escapeGCPTextFilter(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveProjects(t *testing.T) {
	b := &gcpBackend{}

	t.Run("nil creds", func(t *testing.T) {
		got := b.resolveProjects(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("flat fields", func(t *testing.T) {
		got := b.resolveProjects(&logsift.Credentials{
			GCPProjectID:          "my-project",
			GCPServiceAccountJSON: `{"type":"service_account"}`,
		})
		if len(got) != 1 {
			t.Fatalf("expected 1 project, got %d", len(got))
		}
		if got[0].projectID != "my-project" {
			t.Errorf("projectID = %q, want %q", got[0].projectID, "my-project")
		}
	})

	t.Run("multi-project", func(t *testing.T) {
		got := b.resolveProjects(&logsift.Credentials{
			GCPProjects: []logsift.GCPProjectConfig{
				{ProjectID: "proj-1", ServiceAccountJSON: `{"type":"sa"}`},
				{ProjectID: "proj-2"},
			},
		})
		if len(got) != 2 {
			t.Fatalf("expected 2 projects, got %d", len(got))
		}
		if got[0].projectID != "proj-1" || got[1].projectID != "proj-2" {
			t.Errorf("unexpected project IDs: %v", got)
		}
	})

	t.Run("empty project ID skipped", func(t *testing.T) {
		got := b.resolveProjects(&logsift.Credentials{
			GCPProjects: []logsift.GCPProjectConfig{
				{ProjectID: ""},
				{ProjectID: "valid"},
			},
		})
		if len(got) != 1 {
			t.Fatalf("expected 1 project, got %d", len(got))
		}
		if got[0].projectID != "valid" {
			t.Errorf("expected 'valid', got %q", got[0].projectID)
		}
	})
}

