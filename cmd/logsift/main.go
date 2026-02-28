// Package main provides a stdio-based MCP server for searching and reducing
// logs across 11 cloud and infrastructure providers.
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
//	        "AWS_REGION": "us-east-1",
//	        "DD_API_KEY": "your-api-key",
//	        "DD_APP_KEY": "your-app-key"
//	      }
//	    }
//	  }
//	}
//
// Environment variables (only set for backends you use):
//
//   - LOGSIFT_GCP_PROJECTS: Comma-separated GCP project IDs (uses ADC)
//   - GOOGLE_APPLICATION_CREDENTIALS: Path to GCP service account key file (official GCP SDK)
//   - KUBECONFIG: Path to kubeconfig file (defaults to ~/.kube/config)
//   - LOGSIFT_KUBE_CONTEXT: Kubernetes context to use (defaults to current)
//   - LOGSIFT_LOKI_ADDRESS: Loki base URL (e.g., http://localhost:3100)
//   - LOGSIFT_LOKI_TENANT_ID: X-Scope-OrgID for multi-tenant Loki
//   - LOGSIFT_LOKI_USERNAME: Basic auth username for Loki
//   - LOGSIFT_LOKI_PASSWORD: Basic auth password for Loki
//   - LOGSIFT_LOKI_BEARER_TOKEN: Bearer token auth for Loki
//   - AWS_REGION: AWS region for CloudWatch Logs (official AWS SDK)
//   - AWS_PROFILE: AWS SSO/config profile name (official AWS SDK)
//   - LOGSIFT_CW_LOG_GROUP_PREFIX: Default log group prefix (e.g., /ecs/prod/)
//   - AXIOM_TOKEN: Axiom API token (official SDK env var)
//   - AXIOM_ORG_ID: Axiom organization ID (for personal tokens)
//   - AXIOM_URL: Custom Axiom API URL
//   - AZURE_TENANT_ID: Azure AD tenant ID (official SDK env var)
//   - AZURE_CLIENT_ID: Azure service principal app/client ID
//   - AZURE_CLIENT_SECRET: Azure client secret value
//   - LOGSIFT_AZURE_WORKSPACE_ID: Azure Log Analytics workspace GUID
//   - DD_API_KEY: Datadog API key (official env var)
//   - DD_APP_KEY: Datadog application key
//   - DD_SITE: Datadog site (e.g., datadoghq.com, datadoghq.eu)
//   - ELASTICSEARCH_URL: Elasticsearch cluster addresses (official SDK env var)
//   - LOGSIFT_ES_USERNAME: Elasticsearch basic auth username
//   - LOGSIFT_ES_PASSWORD: Elasticsearch basic auth password
//   - LOGSIFT_ES_API_KEY: Elasticsearch API key (base64 id:api_key)
//   - LOGSIFT_ES_CLOUD_ID: Elastic Cloud deployment ID
//   - NEW_RELIC_API_KEY: New Relic user API key (official env var)
//   - NEW_RELIC_ACCOUNT_ID: New Relic account ID
//   - NEW_RELIC_REGION: New Relic region (US or EU)
//   - LOGSIFT_SPLUNK_URL: Splunk base URL (e.g., https://splunk:8089)
//   - LOGSIFT_SPLUNK_TOKEN: Splunk auth token
//   - LOGSIFT_SPLUNK_USERNAME: Splunk username
//   - LOGSIFT_SPLUNK_PASSWORD: Splunk password
//   - SUMOLOGIC_ACCESSID: Sumo Logic access ID (Terraform convention)
//   - SUMOLOGIC_ACCESSKEY: Sumo Logic access key
//   - SUMOLOGIC_BASE_URL: Sumo Logic API endpoint
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fulminate-io/logsift"
	"github.com/fulminate-io/logsift/mcpserver"

	// Blank imports trigger backend and reducer init() registration.
	_ "github.com/fulminate-io/logsift/backend/axiom"
	_ "github.com/fulminate-io/logsift/backend/azuremonitor"
	_ "github.com/fulminate-io/logsift/backend/cloudwatch"
	_ "github.com/fulminate-io/logsift/backend/datadog"
	_ "github.com/fulminate-io/logsift/backend/elasticsearch"
	_ "github.com/fulminate-io/logsift/backend/gcp"
	_ "github.com/fulminate-io/logsift/backend/kubernetes"
	_ "github.com/fulminate-io/logsift/backend/loki"
	_ "github.com/fulminate-io/logsift/backend/newrelic"
	_ "github.com/fulminate-io/logsift/backend/splunk"
	_ "github.com/fulminate-io/logsift/backend/sumologic"
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
	// GOOGLE_APPLICATION_CREDENTIALS is the official GCP SDK env var for SA key path.
	if projects := os.Getenv("LOGSIFT_GCP_PROJECTS"); projects != "" {
		var saJSON string
		if saPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); saPath != "" {
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

	// CloudWatch Logs: use official AWS SDK env vars.
	if region := os.Getenv("AWS_REGION"); region != "" {
		creds.CloudWatchRegion = region
	} else if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		creds.CloudWatchRegion = region
	}
	if profile := os.Getenv("AWS_PROFILE"); profile != "" {
		creds.CloudWatchProfile = profile
	}
	if prefix := os.Getenv("LOGSIFT_CW_LOG_GROUP_PREFIX"); prefix != "" {
		creds.CloudWatchLogGroupPrefix = prefix
	}

	// Axiom: use official AXIOM_* env vars (auto-read by axiom-go SDK too).
	if token := os.Getenv("AXIOM_TOKEN"); token != "" {
		creds.AxiomToken = token
	}
	if orgID := os.Getenv("AXIOM_ORG_ID"); orgID != "" {
		creds.AxiomOrgID = orgID
	}
	if url := os.Getenv("AXIOM_URL"); url != "" {
		creds.AxiomURL = url
	}

	// Azure Monitor: use official AZURE_* env vars for auth (read by DefaultAzureCredential),
	// plus logsift-specific workspace ID.
	if tenantID := os.Getenv("AZURE_TENANT_ID"); tenantID != "" {
		creds.AzureTenantID = tenantID
	}
	if clientID := os.Getenv("AZURE_CLIENT_ID"); clientID != "" {
		creds.AzureClientID = clientID
	}
	if clientSecret := os.Getenv("AZURE_CLIENT_SECRET"); clientSecret != "" {
		creds.AzureClientSecret = clientSecret
	}
	if workspaceID := os.Getenv("LOGSIFT_AZURE_WORKSPACE_ID"); workspaceID != "" {
		creds.AzureWorkspaceID = workspaceID
	}

	// Datadog: use official DD_* env vars.
	if apiKey := os.Getenv("DD_API_KEY"); apiKey != "" {
		creds.DatadogAPIKey = apiKey
	}
	if appKey := os.Getenv("DD_APP_KEY"); appKey != "" {
		creds.DatadogAppKey = appKey
	}
	if site := os.Getenv("DD_SITE"); site != "" {
		creds.DatadogSite = site
	}

	// Elasticsearch / OpenSearch: use official ELASTICSEARCH_URL for addresses.
	if url := os.Getenv("ELASTICSEARCH_URL"); url != "" {
		creds.ElasticsearchAddresses = strings.Split(url, ",")
	}
	if user := os.Getenv("LOGSIFT_ES_USERNAME"); user != "" {
		creds.ElasticsearchUsername = user
	}
	if pass := os.Getenv("LOGSIFT_ES_PASSWORD"); pass != "" {
		creds.ElasticsearchPassword = pass
	}
	if apiKey := os.Getenv("LOGSIFT_ES_API_KEY"); apiKey != "" {
		creds.ElasticsearchAPIKey = apiKey
	}
	if cloudID := os.Getenv("LOGSIFT_ES_CLOUD_ID"); cloudID != "" {
		creds.ElasticsearchCloudID = cloudID
	}

	// New Relic: use official NEW_RELIC_* env vars.
	if apiKey := os.Getenv("NEW_RELIC_API_KEY"); apiKey != "" {
		creds.NewRelicAPIKey = apiKey
	}
	if accountID := os.Getenv("NEW_RELIC_ACCOUNT_ID"); accountID != "" {
		if id, err := strconv.Atoi(accountID); err == nil {
			creds.NewRelicAccountID = id
		}
	}
	if region := os.Getenv("NEW_RELIC_REGION"); region != "" {
		creds.NewRelicRegion = region
	}

	// Splunk: no official SDK env vars, use LOGSIFT_SPLUNK_* prefix.
	if url := os.Getenv("LOGSIFT_SPLUNK_URL"); url != "" {
		creds.SplunkURL = url
	}
	if token := os.Getenv("LOGSIFT_SPLUNK_TOKEN"); token != "" {
		creds.SplunkToken = token
	}
	if user := os.Getenv("LOGSIFT_SPLUNK_USERNAME"); user != "" {
		creds.SplunkUsername = user
	}
	if pass := os.Getenv("LOGSIFT_SPLUNK_PASSWORD"); pass != "" {
		creds.SplunkPassword = pass
	}

	// Sumo Logic: use SUMOLOGIC_* env vars (Terraform/Pulumi convention).
	if accessID := os.Getenv("SUMOLOGIC_ACCESSID"); accessID != "" {
		creds.SumoLogicAccessID = accessID
	}
	if accessKey := os.Getenv("SUMOLOGIC_ACCESSKEY"); accessKey != "" {
		creds.SumoLogicAccessKey = accessKey
	}
	if url := os.Getenv("SUMOLOGIC_BASE_URL"); url != "" {
		creds.SumoLogicURL = url
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
