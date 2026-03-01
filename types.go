package logsift

import "time"

// Query represents a structured log search query.
type Query struct {
	Provider      string
	TextFilter    string
	FieldFilters  map[string]string
	SeverityMin   string
	Source        string
	StartTime     time.Time
	EndTime       time.Time
	RawQuery      string
	MaxRawEntries int
	TokenBudget   int
}

// LogEntry represents a single normalized log entry.
type LogEntry struct {
	Timestamp time.Time
	Severity  string
	Message   string
	Service   string
	Host      string
}

// Cluster represents a group of similar log entries after Drain clustering.
type Cluster struct {
	Template  string
	Severity  string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	Examples  []string
}

// RawResults holds the raw results from a backend search before reduction.
type RawResults struct {
	Entries       []LogEntry
	TotalEstimate int    // estimated total matching entries (may exceed MaxRawEntries)
	ProviderToken string // provider's native pagination token, if any
}

// PaginationCursor encodes state for paginated log searches.
type PaginationCursor struct {
	Provider      string `json:"p"`
	ProviderToken string `json:"pt,omitempty"`
	ClusterOffset int    `json:"co"`
}

// SourceInfo describes an available log source.
type SourceInfo struct {
	Name        string
	Description string
}

// ReductionResult holds the output of the context reduction pipeline.
type ReductionResult struct {
	Clusters    []Cluster
	RawCount    int
	Sampled     bool
	TokensUsed  int
	TokenBudget int
	HasMore     bool
	Cursor      *PaginationCursor
}

// Credentials holds provider credentials for log backends.
// Consumers populate the fields relevant to their configured providers.
type Credentials struct {
	// GCP Cloud Logging
	GCPProjectID          string
	GCPServiceAccountJSON string
	GCPProjects           []GCPProjectConfig

	// Kubernetes
	KubeconfigContent  string
	KubeContext        string
	KubernetesClusters []KubernetesClusterConfig

	// Loki
	LokiAddress     string               // Single Loki instance URL (e.g., http://localhost:3100)
	LokiTenantID    string               // X-Scope-OrgID for multi-tenant Loki
	LokiUsername    string               // Basic auth username
	LokiPassword    string               // Basic auth password
	LokiBearerToken string               // Bearer token auth
	LokiInstances   []LokiInstanceConfig // Multiple Loki instances

	// CloudWatch Logs
	CloudWatchRegion         string                    // AWS region (e.g., us-east-1)
	CloudWatchProfile        string                    // AWS SSO/config profile name
	CloudWatchLogGroupPrefix string                    // Default log group prefix (e.g., /ecs/prod/)
	CloudWatchInstances      []CloudWatchInstanceConfig // Multiple CloudWatch instances

	// Axiom
	AxiomToken    string              // API token (xaat-...) or Personal Access Token (xapt-...)
	AxiomOrgID    string              // Organization ID (required for Personal Access Tokens)
	AxiomURL      string              // Custom API URL (default: https://api.axiom.co)
	AxiomInstances []AxiomInstanceConfig // Multiple Axiom instances

	// Datadog
	DatadogAPIKey    string                  // API key (identifies organization)
	DatadogAppKey    string                  // Application key (carries permissions)
	DatadogSite      string                  // Datadog site (e.g., datadoghq.com, datadoghq.eu, us3.datadoghq.com)
	DatadogInstances []DatadogInstanceConfig // Multiple Datadog instances

	// Azure Monitor Log Analytics
	AzureTenantID     string                       // Azure AD tenant ID
	AzureClientID     string                       // Service principal app/client ID
	AzureClientSecret string                       // Client secret value
	AzureWorkspaceID  string                       // Log Analytics workspace GUID
	AzureInstances    []AzureMonitorInstanceConfig  // Multiple workspaces

	// Sumo Logic
	SumoLogicAccessID  string                      // Access ID
	SumoLogicAccessKey string                      // Access Key
	SumoLogicURL       string                      // API endpoint (e.g., https://api.us2.sumologic.com)
	SumoLogicInstances []SumoLogicInstanceConfig   // Multiple instances

	// New Relic
	NewRelicAPIKey     string                     // User API key (NRAK-...)
	NewRelicAccountID  int                        // Account ID
	NewRelicRegion     string                     // "US" (default) or "EU"
	NewRelicInstances  []NewRelicInstanceConfig   // Multiple accounts

	// Splunk
	SplunkURL          string                  // Base URL (e.g., https://splunk.example.com:8089)
	SplunkToken        string                  // Bearer or Splunk auth token
	SplunkUsername     string                  // Username for session-based auth
	SplunkPassword     string                  // Password for session-based auth
	SplunkTLSSkipVerify bool                   // Skip TLS verification (dev only)
	SplunkInstances    []SplunkInstanceConfig  // Multiple Splunk instances

	// Elasticsearch / OpenSearch
	ElasticsearchAddresses []string                       // Cluster addresses (e.g., https://localhost:9200)
	ElasticsearchUsername  string                          // Basic auth username
	ElasticsearchPassword  string                          // Basic auth password
	ElasticsearchAPIKey    string                          // API key (base64-encoded id:api_key)
	ElasticsearchCloudID   string                          // Elastic Cloud deployment ID
	ElasticsearchInstances []ElasticsearchInstanceConfig   // Multiple instances
}

// GCPProjectConfig holds credentials for a single GCP project.
type GCPProjectConfig struct {
	Name              string
	ProjectID         string
	ServiceAccountJSON string
}

// KubernetesClusterConfig holds credentials for a single Kubernetes cluster.
type KubernetesClusterConfig struct {
	Name              string
	KubeconfigContent string
	Context           string
}

// LokiInstanceConfig holds credentials for a single Loki instance.
type LokiInstanceConfig struct {
	Name        string
	Address     string // Base URL (e.g., http://loki-query-frontend:3100)
	TenantID    string // X-Scope-OrgID header value
	Username    string // Basic auth username
	Password    string // Basic auth password
	BearerToken string // Bearer token auth
}

// CloudWatchInstanceConfig holds credentials for a single CloudWatch Logs instance.
type CloudWatchInstanceConfig struct {
	Name            string
	Region          string // AWS region (e.g., us-east-1)
	Profile         string // AWS SSO/config profile name
	AccessKeyID     string // Static credentials (optional, uses default chain if empty)
	SecretAccessKey string // Static credentials (optional)
	SessionToken    string // Session token for temporary credentials (optional)
	LogGroupPrefix  string // Default log group prefix (e.g., /ecs/prod/)
}

// AxiomInstanceConfig holds credentials for a single Axiom instance.
type AxiomInstanceConfig struct {
	Name   string // Display name for this instance
	Token  string // API token or Personal Access Token
	OrgID  string // Organization ID (required for Personal Access Tokens)
	URL    string // Custom API URL (e.g., https://api.eu.axiom.co)
}

// DatadogInstanceConfig holds credentials for a single Datadog instance.
type DatadogInstanceConfig struct {
	Name   string // Display name for this instance
	APIKey string // API key (identifies organization)
	AppKey string // Application key (carries permissions)
	Site   string // Datadog site (e.g., datadoghq.com, datadoghq.eu)
}

// AzureMonitorInstanceConfig holds credentials for a single Azure Monitor Log Analytics workspace.
type AzureMonitorInstanceConfig struct {
	Name         string // Display name for this workspace
	TenantID     string // Azure AD tenant ID
	ClientID     string // Service principal app/client ID
	ClientSecret string // Client secret value
	WorkspaceID  string // Log Analytics workspace GUID
}

// SumoLogicInstanceConfig holds credentials for a single Sumo Logic deployment.
type SumoLogicInstanceConfig struct {
	Name      string // Display name for this instance
	AccessID  string // Access ID
	AccessKey string // Access Key
	URL       string // API endpoint (e.g., https://api.us2.sumologic.com)
}

// NewRelicInstanceConfig holds credentials for a single New Relic account.
type NewRelicInstanceConfig struct {
	Name      string // Display name for this account
	APIKey    string // User API key (NRAK-...)
	AccountID int    // Account ID
	Region    string // "US" (default) or "EU"
}

// SplunkInstanceConfig holds credentials for a single Splunk instance.
type SplunkInstanceConfig struct {
	Name           string // Display name for this instance
	URL            string // Base URL (e.g., https://splunk.example.com:8089)
	Token          string // Bearer or Splunk auth token
	Username       string // Username for session-based auth
	Password       string // Password for session-based auth
	TLSSkipVerify  bool   // Skip TLS verification (dev only)
}

// ElasticsearchInstanceConfig holds credentials for a single Elasticsearch or OpenSearch instance.
type ElasticsearchInstanceConfig struct {
	Name      string   // Display name for this instance
	Addresses []string // Cluster addresses (e.g., https://localhost:9200)
	Username  string   // Basic auth username
	Password  string   // Basic auth password
	APIKey    string   // API key (base64-encoded id:api_key, ES only)
	CloudID   string   // Elastic Cloud deployment ID (ES only)
	CACert    string   // PEM-encoded CA certificate
}

// SearchLogsInput is the JSON input schema for the search_logs tool.
type SearchLogsInput struct {
	Provider     string            `json:"provider"`
	TextFilter   string            `json:"text_filter,omitempty"`
	FieldFilters map[string]string `json:"field_filters,omitempty"`
	SeverityMin  string            `json:"severity_min,omitempty"`
	Source       string            `json:"source,omitempty"`
	TimeRange    string            `json:"time_range,omitempty"`
	RawQuery     string            `json:"raw_query,omitempty"`
	Mode         string            `json:"mode,omitempty"`
	TokenBudget  int               `json:"token_budget,omitempty"`
	Cursor       string            `json:"cursor,omitempty"`

	// Time window behavior.
	ExactTimeRange bool `json:"exact_time_range,omitempty"` // If true, do not auto-expand the time window on zero results

	// Reducer tuning (optional, for domain-specific control).
	SuppressPatterns []string `json:"suppress_patterns,omitempty"` // Regex patterns to collapse into noise summary
	SeverityKeywords []string `json:"severity_keywords,omitempty"` // Extra words that trigger INFO→WARN uplift
	NoiseThreshold   int      `json:"noise_threshold,omitempty"`   // Min count to consider a cluster noise (0=auto)
}

// ListLogSourcesInput is the JSON input schema for the list_log_sources tool.
type ListLogSourcesInput struct {
	Provider string `json:"provider"`
	Prefix   string `json:"prefix,omitempty"`
}
