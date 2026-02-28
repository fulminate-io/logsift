// Package main provides a stdio-based MCP server for searching and reducing
// logs from GCP Cloud Logging, Kubernetes pod logs, Loki, and CloudWatch Logs.
//
// Configure as an MCP server in Claude Code or any MCP-compatible client:
//
//	{
//	  "mcpServers": {
//	    "logsift": {
//	      "command": "logsift",
//	      "env": {
//	        "LOGSIFT_GCP_PROJECTS": "my-project-1,my-project-2",
//	        "KUBECONFIG": "~/.kube/config",
//	        "LOGSIFT_LOKI_ADDRESS": "http://localhost:3100",
//	        "LOGSIFT_CW_REGION": "us-east-1"
//	      }
//	    }
//	  }
//	}
//
// Environment variables:
//
//   - LOGSIFT_GCP_PROJECTS: Comma-separated GCP project IDs (uses ADC)
//   - LOGSIFT_GCP_SERVICE_ACCOUNT_JSON: Path to service account key file
//   - KUBECONFIG: Path to kubeconfig file (defaults to ~/.kube/config)
//   - LOGSIFT_KUBE_CONTEXT: Kubernetes context to use (defaults to current)
//   - LOGSIFT_LOKI_ADDRESS: Loki base URL (e.g., http://localhost:3100)
//   - LOGSIFT_LOKI_TENANT_ID: X-Scope-OrgID for multi-tenant Loki
//   - LOGSIFT_LOKI_USERNAME: Basic auth username for Loki
//   - LOGSIFT_LOKI_PASSWORD: Basic auth password for Loki
//   - LOGSIFT_CW_REGION: AWS region for CloudWatch Logs (e.g., us-east-1)
//   - LOGSIFT_CW_PROFILE: AWS SSO/config profile name (optional)
//   - LOGSIFT_CW_LOG_GROUP_PREFIX: Default log group prefix (e.g., /ecs/prod/)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fulminate-io/logsift"
	"github.com/fulminate-io/logsift/mcpserver"

	// Blank imports trigger backend and reducer init() registration.
	_ "github.com/fulminate-io/logsift/backend/cloudwatch"
	_ "github.com/fulminate-io/logsift/backend/gcp"
	_ "github.com/fulminate-io/logsift/backend/kubernetes"
	_ "github.com/fulminate-io/logsift/backend/loki"
	_ "github.com/fulminate-io/logsift/reducer"
)

var version = "dev"

func main() {
	creds := buildCredentials()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req mcpserver.Request
		if err := json.Unmarshal(line, &req); err != nil {
			writeResponse(mcpserver.NewErrorResponse(nil, mcpserver.ErrCodeParse, "invalid JSON", nil))
			continue
		}

		resp := handleRequest(creds, &req)
		if resp != nil {
			writeResponse(resp)
		}
	}
}

func buildCredentials() *logsift.Credentials {
	creds := &logsift.Credentials{}

	// GCP: build project configs from env.
	if projects := os.Getenv("LOGSIFT_GCP_PROJECTS"); projects != "" {
		var saJSON string
		if saPath := os.Getenv("LOGSIFT_GCP_SERVICE_ACCOUNT_JSON"); saPath != "" {
			if data, err := os.ReadFile(saPath); err == nil {
				saJSON = string(data)
			}
		}
		for _, p := range strings.Split(projects, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			creds.GCPProjects = append(creds.GCPProjects, logsift.GCPProjectConfig{
				Name:               p,
				ProjectID:          p,
				ServiceAccountJSON: saJSON,
			})
		}
	}

	// Kubernetes: load kubeconfig.
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
	}
	if kubeconfigPath != "" {
		if data, err := os.ReadFile(kubeconfigPath); err == nil {
			creds.KubeconfigContent = string(data)
		}
	}
	if ctx := os.Getenv("LOGSIFT_KUBE_CONTEXT"); ctx != "" {
		creds.KubeContext = ctx
	}

	// Loki: load address and auth from env.
	if addr := os.Getenv("LOGSIFT_LOKI_ADDRESS"); addr != "" {
		creds.LokiAddress = addr
	}
	if tenant := os.Getenv("LOGSIFT_LOKI_TENANT_ID"); tenant != "" {
		creds.LokiTenantID = tenant
	}
	if user := os.Getenv("LOGSIFT_LOKI_USERNAME"); user != "" {
		creds.LokiUsername = user
	}
	if pass := os.Getenv("LOGSIFT_LOKI_PASSWORD"); pass != "" {
		creds.LokiPassword = pass
	}
	if token := os.Getenv("LOGSIFT_LOKI_BEARER_TOKEN"); token != "" {
		creds.LokiBearerToken = token
	}

	// CloudWatch Logs: load region, profile, and prefix from env.
	if region := os.Getenv("LOGSIFT_CW_REGION"); region != "" {
		creds.CloudWatchRegion = region
	}
	if profile := os.Getenv("LOGSIFT_CW_PROFILE"); profile != "" {
		creds.CloudWatchProfile = profile
	}
	if prefix := os.Getenv("LOGSIFT_CW_LOG_GROUP_PREFIX"); prefix != "" {
		creds.CloudWatchLogGroupPrefix = prefix
	}

	return creds
}

func handleRequest(creds *logsift.Credentials, req *mcpserver.Request) *mcpserver.Response {
	switch req.Method {
	case "initialize":
		return mcpserver.NewResponse(req.ID, mcpserver.InitializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities: mcpserver.ServerCapabilities{
				Tools: &mcpserver.ToolsCapability{},
			},
			ServerInfo: mcpserver.EntityInfo{
				Name:    "logsift",
				Version: version,
			},
		})

	case "notifications/initialized":
		return nil

	case "tools/list":
		return mcpserver.NewResponse(req.ID, mcpserver.ToolsListResult{
			Tools: listTools(),
		})

	case "tools/call":
		var params mcpserver.CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return mcpserver.NewErrorResponse(req.ID, mcpserver.ErrCodeInvalidParams, "invalid params: "+err.Error(), nil)
		}
		result := callTool(creds, &params)
		return mcpserver.NewResponse(req.ID, result)

	case "ping":
		return mcpserver.NewResponse(req.ID, map[string]string{"pong": "ok"})

	default:
		return mcpserver.NewErrorResponse(req.ID, mcpserver.ErrCodeMethodNotFound, "unknown method: "+req.Method, nil)
	}
}

func listTools() []mcpserver.Tool {
	providers := logsift.RegisteredBackends()
	providerList := strings.Join(providers, ", ")

	return []mcpserver.Tool{
		{
			Name: "search_logs",
			Description: "Search logs from cloud and infrastructure providers. " +
				"Returns clustered, deduplicated log entries sorted by signal strength. " +
				"Available providers: " + providerList + ". " +
				"Use list_log_sources to discover available log sources before searching.",
			InputSchema: mcpserver.InputSchema{
				Type: "object",
				Properties: map[string]mcpserver.Property{
					"provider": {
						Type:        "string",
						Description: "Log provider to query. Available: " + providerList,
						Enum:        providers,
					},
					"text_filter": {
						Type:        "string",
						Description: "Substring or regex to match in log message body",
					},
					"field_filters": {
						Type:        "object",
						Description: "Structured field filters: service, host, namespace, pod, container, level. Backend maps these to native field names.",
					},
					"severity_min": {
						Type:        "string",
						Description: "Minimum severity: TRACE, DEBUG, INFO (default), WARN, ERROR, CRITICAL",
						Enum:        []string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"},
					},
					"source": {
						Type:        "string",
						Description: "Log source. GCP: log name (e.g., stderr). Kubernetes: namespace. Use list_log_sources to discover names.",
					},
					"time_range": {
						Type:        "string",
						Description: "Time range as Go duration (15m, 1h, 6h, 24h). Default: 15m. Auto-expands on zero results.",
					},
					"raw_query": {
						Type:        "string",
						Description: "Raw provider-native query. GCP: Advanced Logs Filter. Kubernetes: label selector.",
					},
					"mode": {
						Type:        "string",
						Description: "Output format: text (default) or json",
						Enum:        []string{"text", "json"},
					},
					"token_budget": {
						Type:        "integer",
						Description: "Max token budget for results. Default: 4000",
					},
					"cursor": {
						Type:        "string",
						Description: "Opaque pagination cursor from a previous search_logs call",
					},
					"suppress_patterns": {
						Type:        "array",
						Description: "Regex patterns for clusters to collapse into noise summary. Use for known noisy patterns (e.g., [\"health.check\", \"processing.*request\"]).",
						Items:       &mcpserver.Property{Type: "string"},
					},
					"severity_keywords": {
						Type:        "array",
						Description: "Extra words that trigger INFO->WARN severity uplift. Use for domain-specific problem indicators (e.g., [\"quota\", \"throttle\", \"rate.limit\"]).",
						Items:       &mcpserver.Property{Type: "string"},
					},
					"noise_threshold": {
						Type:        "integer",
						Description: "Minimum occurrence count for a cluster to be classified as noise. 0 (default) auto-detects based on count distribution.",
					},
				},
				Required: []string{"provider"},
			},
		},
		{
			Name: "list_log_sources",
			Description: "List available log sources. GCP: log names. Kubernetes: namespaces. " +
				"Available providers: " + providerList + ". " +
				"Use to discover source names before calling search_logs.",
			InputSchema: mcpserver.InputSchema{
				Type: "object",
				Properties: map[string]mcpserver.Property{
					"provider": {
						Type:        "string",
						Description: "Log provider to query. Available: " + providerList,
						Enum:        providers,
					},
					"prefix": {
						Type:        "string",
						Description: "Optional prefix filter to narrow results",
					},
				},
				Required: []string{"provider"},
			},
		},
	}
}

func callTool(creds *logsift.Credentials, params *mcpserver.CallToolParams) *mcpserver.CallToolResult {
	switch params.Name {
	case "search_logs":
		return handleSearchLogs(creds, params.Arguments)
	case "list_log_sources":
		return handleListLogSources(creds, params.Arguments)
	default:
		return mcpserver.ErrorResult("unknown tool: " + params.Name)
	}
}

func handleSearchLogs(creds *logsift.Credentials, args json.RawMessage) *mcpserver.CallToolResult {
	var input logsift.SearchLogsInput
	if err := json.Unmarshal(args, &input); err != nil {
		return mcpserver.ErrorResult("Error parsing arguments: " + err.Error())
	}

	if input.Provider == "" {
		available := logsift.Available(creds)
		if len(available) == 1 {
			input.Provider = available[0]
		} else if len(available) > 1 {
			return mcpserver.ErrorResult("Multiple providers configured (" +
				strings.Join(available, ", ") + "). Specify which one with the 'provider' parameter.")
		} else {
			return mcpserver.ErrorResult("No provider specified and no credentials configured. Available backends: " +
				strings.Join(logsift.RegisteredBackends(), ", "))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := logsift.Search(ctx, input.Provider, creds, &input)
	if err != nil {
		return mcpserver.ErrorResult(fmt.Sprintf("Error: %s", err))
	}
	return mcpserver.TextResult(result)
}

func handleListLogSources(creds *logsift.Credentials, args json.RawMessage) *mcpserver.CallToolResult {
	var input logsift.ListLogSourcesInput
	if len(args) > 0 {
		if err := json.Unmarshal(args, &input); err != nil {
			return mcpserver.ErrorResult("Error parsing arguments: " + err.Error())
		}
	}

	if input.Provider == "" {
		available := logsift.Available(creds)
		if len(available) == 1 {
			input.Provider = available[0]
		} else if len(available) > 1 {
			return mcpserver.ErrorResult("Multiple providers configured (" +
				strings.Join(available, ", ") + "). Specify which one with the 'provider' parameter.")
		} else {
			return mcpserver.ErrorResult("No provider specified and no credentials configured. Available backends: " +
				strings.Join(logsift.RegisteredBackends(), ", "))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sources, err := logsift.ListSources(ctx, input.Provider, creds, input.Prefix)
	if err != nil {
		return mcpserver.ErrorResult(fmt.Sprintf("Error listing sources: %s", err))
	}

	return mcpserver.TextResult(formatSources(sources, input.Provider))
}

func formatSources(sources []logsift.SourceInfo, provider string) string {
	if len(sources) == 0 {
		return fmt.Sprintf("[list_log_sources] 0 sources found (%s)", provider)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "[list_log_sources] %d sources found (%s)\n\n", len(sources), provider)
	for _, s := range sources {
		sb.WriteString("  ")
		sb.WriteString(s.Name)
		if s.Description != "" {
			sb.WriteString("  (")
			sb.WriteString(s.Description)
			sb.WriteString(")")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func writeResponse(resp *mcpserver.Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	fmt.Fprintln(os.Stdout, string(data))
}
