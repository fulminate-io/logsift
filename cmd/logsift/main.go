// Package main provides a stdio-based MCP server for searching and reducing
// logs from GCP Cloud Logging and Kubernetes pod logs.
//
// Configure as an MCP server in Claude Code or any MCP-compatible client:
//
//	{
//	  "mcpServers": {
//	    "logsift": {
//	      "command": "logsift",
//	      "env": {
//	        "LOGSIFT_GCP_PROJECTS": "my-project-1,my-project-2",
//	        "KUBECONFIG": "~/.kube/config"
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
	_ "github.com/fulminate-io/logsift/backend/gcp"
	_ "github.com/fulminate-io/logsift/backend/kubernetes"
	_ "github.com/fulminate-io/logsift/reducer"
)

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
				Version: "0.1.0",
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
				},
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
		// Pick the first available provider.
		available := logsift.Available(creds)
		if len(available) > 0 {
			input.Provider = available[0]
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
		if len(available) > 0 {
			input.Provider = available[0]
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
