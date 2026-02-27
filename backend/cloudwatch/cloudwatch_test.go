package cloudwatch

import (
	"testing"

	logsift "github.com/fulminate-io/logsift"
)

func TestParseLogMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantMsg  string
		wantSev  string
	}{
		{
			name:    "plain JSON with level and message",
			input:   `{"level":"error","ts":"2026-02-27T17:54:58.111Z","msg":"Operation failed with internal error."}`,
			wantMsg: "Operation failed with internal error.",
			wantSev: logsift.SeverityError,
		},
		{
			name:    "structlog JSON with event field",
			input:   `{"event": "S3 data file not found for successful extraction run", "level": "error", "lineno": 90}`,
			wantMsg: "S3 data file not found for successful extraction run",
			wantSev: logsift.SeverityError,
		},
		{
			name:    "logger-prefixed JSON with event",
			input:   `[src.app.services_v2.extract.extraction_utils] {"event": "S3 data file not found", "level": "error"}`,
			wantMsg: "S3 data file not found",
			wantSev: logsift.SeverityError,
		},
		{
			name:    "logger-prefixed JSON with warning level",
			input:   `[platform_api] {"event": "Request validation error", "level": "warning"}`,
			wantMsg: "Request validation error",
			wantSev: logsift.SeverityWarn,
		},
		{
			name:    "JSON with message field and warn level",
			input:   `{"message":"Activity failed","timestamp":1772214194082,"level":"warn"}`,
			wantMsg: "Activity failed",
			wantSev: logsift.SeverityWarn,
		},
		{
			name:    "severity prefix with message",
			input:   `ERROR some operation failed badly`,
			wantMsg: "some operation failed badly",
			wantSev: logsift.SeverityError,
		},
		{
			name:    "severity prefix with JSON",
			input:   `ERROR {"msg":"database connection failed","component":"db"}`,
			wantMsg: "database connection failed",
			wantSev: logsift.SeverityError,
		},
		{
			name:    "logrus format with time and level",
			input:   `time="2026-02-27T17:49:01Z" level=warning msg="Watch channel closed. Reconnecting..."`,
			wantMsg: `time="2026-02-27T17:49:01Z" level=warning msg="Watch channel closed. Reconnecting..."`,
			wantSev: logsift.SeverityWarn,
		},
		{
			name:    "plain text INFO from PostgreSQL",
			input:   `2026-02-27 18:20:07 UTC::@:[22977]:LOG:  update plans task started`,
			wantMsg: `2026-02-27 18:20:07 UTC::@:[22977]:LOG:  update plans task started`,
			wantSev: logsift.SeverityInfo,
		},
		{
			name:    "K8s audit log JSON (no standard message field)",
			input:   `{"annotations":{"authorization.k8s.io/decision":"allow"},"apiVersion":"audit.k8s.io/v1","kind":"Event","level":"RequestResponse"}`,
			wantSev: logsift.SeverityInfo, // "RequestResponse" is not a severity
		},
		{
			name:    "INFO prefix with logger and JSON",
			input:   `INFO  [src.core.logging.fastapi] {"event": "processing http request", "level": "info"}`,
			wantMsg: "processing http request",
			wantSev: logsift.SeverityInfo,
		},
		{
			name:    "empty message",
			input:   "",
			wantMsg: "",
			wantSev: logsift.SeverityInfo,
		},
		{
			name:    "container log wrapper with inner JSON",
			input:   `{"time":"2026-02-27T18:47:41.316Z","stream":"stderr","_p":"F","log":"{\"event\": \"Starting request\", \"level\": \"info\", \"logger\": \"platform_api\"}"}`,
			wantMsg: "Starting request",
			wantSev: logsift.SeverityInfo,
		},
		{
			name:    "container log wrapper with logger-prefixed inner",
			input:   `{"time":"2026-02-27T18:47:41.316Z","stream":"stderr","_p":"F","log":"INFO  [platform_api] {\"event\": \"Starting request\", \"level\": \"info\"}"}`,
			wantMsg: "Starting request",
			wantSev: logsift.SeverityInfo,
		},
		{
			name:    "container log wrapper with error level inner",
			input:   `{"time":"2026-02-27T18:06:21.792Z","stream":"stderr","_p":"F","log":"{\"level\":\"error\",\"ts\":\"2026-02-27T18:06:21.792Z\",\"msg\":\"Reconciler error\"}"}`,
			wantMsg: "Reconciler error",
			wantSev: logsift.SeverityError,
		},
		{
			name:    "nested message object (AMP alertmanager)",
			input:   `{"component":"alertmanager","message":{"level":"ERROR","log":"Notify for alerts failed"}}`,
			wantMsg: "Notify for alerts failed",
			wantSev: logsift.SeverityError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMsg, gotSev := parseLogMessage(tt.input)
			if tt.wantMsg != "" && gotMsg != tt.wantMsg {
				t.Errorf("message:\n  got:  %q\n  want: %q", gotMsg, tt.wantMsg)
			}
			if gotSev != tt.wantSev {
				t.Errorf("severity: got %q, want %q", gotSev, tt.wantSev)
			}
		})
	}
}

func TestExtractServiceFromLogGroup(t *testing.T) {
	tests := []struct {
		logGroup string
		want     string
	}{
		{"/ecs/prod/api-server", "api-server"},
		{"/aws/lambda/my-function", "my-function"},
		{"/llamacloud/platform-staging/application", "application"},
		{"/aws/rds/cluster/llamacloud-platform-aurora-cluster/postgresql", "postgresql"},
		{"my-log-group", "my-log-group"},
	}

	for _, tt := range tests {
		t.Run(tt.logGroup, func(t *testing.T) {
			got := extractServiceFromLogGroup(tt.logGroup)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
