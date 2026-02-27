package logsift

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
	FieldMappingDatadog = FieldMapping{
		FieldService: "service",
		FieldHost:    "host",
		FieldLevel:   "status",
		FieldTraceID: "trace_id",
	}
	FieldMappingLoki = FieldMapping{
		FieldService:   "service_name",
		FieldHost:      "hostname",
		FieldNamespace: "namespace",
		FieldPod:       "pod",
		FieldContainer: "container",
		FieldLevel:     "level",
	}
	FieldMappingElastic = FieldMapping{
		FieldService:   "service.name",
		FieldHost:      "host.name",
		FieldNamespace: "kubernetes.namespace",
		FieldPod:       "kubernetes.pod.name",
		FieldContainer: "container.name",
		FieldLevel:     "log.level",
	}
	FieldMappingGCP = FieldMapping{
		FieldService:   "resource.labels.service_name",
		FieldHost:      "resource.labels.instance_id",
		FieldNamespace: "resource.labels.namespace_name",
		FieldPod:       "resource.labels.pod_name",
		FieldContainer: "resource.labels.container_name",
		FieldLevel:     "severity",
	}
	FieldMappingSplunk = FieldMapping{
		FieldService: "service",
		FieldHost:    "host",
		FieldLevel:   "severity",
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
func MapFieldFilters(filters map[string]string, mapping FieldMapping) map[string]string {
	if len(filters) == 0 {
		return nil
	}
	result := make(map[string]string, len(filters))
	for k, v := range filters {
		if native, ok := mapping[k]; ok {
			result[native] = v
		} else {
			result[k] = v
		}
	}
	return result
}
