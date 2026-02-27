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
