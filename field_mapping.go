package logsift

import "strings"

// Canonical field names the LLM uses in field_filters.
// Backends translate these to native equivalents.
const (
	FieldService   = "service"
	FieldHost      = "host"
	FieldNamespace = "namespace"
	FieldPod       = "pod"
	FieldContainer = "container"
	FieldLevel     = "level"
	FieldTraceID   = "trace_id"
)

// FieldMapping maps canonical names to provider-native names.
type FieldMapping map[string]string

// Per-provider field mappings.
var (
	FieldMappingCloudWatch = FieldMapping{
		// CloudWatch has no native structured fields — these become filter pattern text matches
	}
	FieldMappingLoki = FieldMapping{
		FieldService:   "service_name",
		FieldHost:      "node",
		FieldNamespace: "namespace",
		FieldPod:       "pod",
		FieldContainer: "container",
		FieldLevel:     "level",
	}
	FieldMappingGCP = FieldMapping{
		FieldService:   "resource.labels.service_name",
		FieldHost:      "resource.labels.instance_id",
		FieldNamespace: "resource.labels.namespace_name",
		FieldPod:       "resource.labels.pod_name",
		FieldContainer: "resource.labels.container_name",
		FieldLevel:     "severity",
	}
	FieldMappingAxiom = FieldMapping{
		FieldService:   "service",
		FieldHost:      "host",
		FieldNamespace: "kubernetes.namespace_name",
		FieldPod:       "kubernetes.pod_name",
		FieldContainer: "kubernetes.container_name",
		FieldLevel:     "level",
		FieldTraceID:   "trace_id",
	}
	FieldMappingAzureMonitor = FieldMapping{
		FieldService:   "service",
		FieldHost:      "Computer",
		FieldNamespace: "PodNamespace",
		FieldPod:       "PodName",
		FieldContainer: "ContainerName",
		FieldLevel:     "LogLevel",
	}
	FieldMappingElasticsearch = FieldMapping{
		FieldService:   "service.name",
		FieldHost:      "host.name",
		FieldNamespace: "kubernetes.namespace",
		FieldPod:       "kubernetes.pod.name",
		FieldContainer: "kubernetes.container.name",
		FieldLevel:     "log.level",
		FieldTraceID:   "trace.id",
	}
	FieldMappingSumoLogic = FieldMapping{
		FieldService:   "_sourceCategory",
		FieldHost:      "_sourceHost",
		FieldNamespace: "namespace",
		FieldPod:       "pod",
		FieldContainer: "container",
		FieldLevel:     "level",
	}
	FieldMappingNewRelic = FieldMapping{
		FieldService:   "service.name",
		FieldHost:      "hostname",
		FieldNamespace: "kubernetes.namespace_name",
		FieldPod:       "kubernetes.pod_name",
		FieldContainer: "kubernetes.container_name",
		FieldLevel:     "level",
		FieldTraceID:   "trace.id",
	}
	FieldMappingSplunk = FieldMapping{
		FieldService:   "service",
		FieldHost:      "host",
		FieldNamespace: "namespace",
		FieldPod:       "pod",
		FieldContainer: "container_name",
		FieldLevel:     "level",
	}
	FieldMappingDatadog = FieldMapping{
		FieldService:   "service",
		FieldHost:      "host",
		FieldNamespace: "kube_namespace",
		FieldPod:       "kube_pod_name",
		FieldContainer: "kube_container_name",
		FieldLevel:     "status",
		FieldTraceID:   "trace_id",
	}
	// FieldMappingKubernetes is an identity mapping — the K8s backend interprets
	// canonical field names directly via client-side filtering.
	FieldMappingKubernetes = FieldMapping{
		FieldService:   "service",
		FieldHost:      "host",
		FieldNamespace: "namespace",
		FieldPod:       "pod",
		FieldContainer: "container",
		FieldLevel:     "level",
	}
)

// MapFieldFilters translates canonical field names to provider-native names.
// Unknown names are passed through unchanged (for provider-specific fields).
// Both field names and values are sanitized to prevent query injection from
// LLM-generated tool calls.
func MapFieldFilters(filters map[string]string, mapping FieldMapping) map[string]string {
	if len(filters) == 0 {
		return nil
	}
	result := make(map[string]string, len(filters))
	for k, v := range filters {
		k = SanitizeFieldName(k)
		v = SanitizeQueryValue(v)
		if k == "" {
			continue
		}
		if native, ok := mapping[k]; ok {
			result[native] = v
		} else {
			result[k] = v
		}
	}
	return result
}

// SanitizeFieldName restricts field names to safe characters: alphanumeric,
// dots, underscores, and hyphens. This prevents injection of query operators
// through LLM-generated field names in MCP tool calls.
func SanitizeFieldName(name string) string {
	var sb strings.Builder
	sb.Grow(len(name))
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// SanitizeSourceName restricts source/index/dataset names to safe characters.
// Sources typically contain alphanumeric, dots, underscores, hyphens, slashes,
// and wildcards (*).
func SanitizeSourceName(name string) string {
	var sb strings.Builder
	sb.Grow(len(name))
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' || r == '/' || r == '*' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// SanitizeQueryValue strips characters that could serve as query operators or
// control flow in log query languages (APL, KQL, SPL, NRQL, Lucene, Datadog).
// This is a defense-in-depth measure — backend-specific escape functions provide
// the primary escaping, but this strips universally dangerous patterns that an
// LLM might hallucinate into field values via MCP tool calls.
//
// Allowed: alphanumeric, spaces, dots, hyphens, underscores, colons, slashes,
// at-signs, plus, equals, commas. Stripped: pipes, semicolons, backticks,
// parentheses, brackets, braces, quotes, backslashes, newlines, dollar signs.
func SanitizeQueryValue(value string) string {
	var sb strings.Builder
	sb.Grow(len(value))
	for _, r := range value {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			sb.WriteRune(r)
		case r == ' ' || r == '.' || r == '-' || r == '_' || r == ':' ||
			r == '/' || r == '@' || r == '+' || r == '=' || r == ',':
			sb.WriteRune(r)
		// All other characters (pipes, semicolons, backticks, parens,
		// brackets, braces, quotes, backslashes, newlines, $, etc.)
		// are stripped to prevent query injection.
		}
	}
	return sb.String()
}
