package logsift

import (
	"testing"
)

func TestMapFieldFilters(t *testing.T) {
	tests := []struct {
		name     string
		filters  map[string]string
		mapping  FieldMapping
		expected map[string]string
	}{
		{
			name:     "nil filters",
			filters:  nil,
			mapping:  FieldMappingLoki,
			expected: nil,
		},
		{
			name:     "empty filters",
			filters:  map[string]string{},
			mapping:  FieldMappingLoki,
			expected: nil,
		},
		{
			name:    "loki mapping",
			filters: map[string]string{"service": "api", "host": "web-01"},
			mapping: FieldMappingLoki,
			expected: map[string]string{
				"service_name": "api",
				"node":         "web-01",
			},
		},
		{
			name:    "unknown fields pass through",
			filters: map[string]string{"service": "api", "custom_field": "value"},
			mapping: FieldMappingKubernetes,
			expected: map[string]string{
				"service":      "api",
				"custom_field": "value",
			},
		},
		{
			name:    "GCP mapping",
			filters: map[string]string{"level": "ERROR", "pod": "web-abc123"},
			mapping: FieldMappingGCP,
			expected: map[string]string{
				"severity":                 "ERROR",
				"resource.labels.pod_name": "web-abc123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapFieldFilters(tt.filters, tt.mapping)
			if tt.expected == nil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if len(got) != len(tt.expected) {
				t.Fatalf("expected %d fields, got %d: %v", len(tt.expected), len(got), got)
			}
			for k, v := range tt.expected {
				if got[k] != v {
					t.Errorf("field %q: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestSanitizeFieldName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"service", "service"},
		{"host.name", "host.name"},
		{"kubernetes_namespace", "kubernetes_namespace"},
		{"my-field", "my-field"},
		// Injection attempts
		{"field | delete", "fielddelete"},
		{"field'; DROP TABLE", "fieldDROPTABLE"},
		{`field" OR 1=1 --`, "fieldOR11--"},
		{"field\nwhere true", "fieldwheretrue"},
		{"field$(rm -rf /)", "fieldrm-rf"},
		{"field`cmd`", "fieldcmd"},
		{"", ""},
	}
	for _, tt := range tests {
		got := SanitizeFieldName(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeFieldName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeSourceName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"my-index", "my-index"},
		{"logs-2024.*", "logs-2024.*"},
		{"_sourceCategory/prod", "_sourceCategory/prod"},
		{"ContainerLogV2", "ContainerLogV2"},
		// Injection attempts
		{"index; DELETE *", "indexDELETE*"},
		{"index | drop table", "indexdroptable"},
		{`index" OR true`, "indexORtrue"},
		{"", ""},
	}
	for _, tt := range tests {
		got := SanitizeSourceName(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeSourceName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeQueryValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Normal values pass through.
		{"my-service", "my-service"},
		{"web-01.prod.example.com", "web-01.prod.example.com"},
		{"kube-system", "kube-system"},
		{"user@example.com", "user@example.com"},
		{"v1.2.3+build", "v1.2.3+build"},
		// Injection attempts are stripped.
		{`value"; DROP TABLE logs`, "value DROP TABLE logs"},
		{"value | rm -rf /", "value  rm -rf /"},
		{"value'; DELETE FROM", "value DELETE FROM"},
		{"value$(cmd)", "valuecmd"},
		{"value`whoami`", "valuewhoami"},
		{"value\n| where true", "value where true"},
		{"value{key: injection}", "valuekey: injection"},
		{"", ""},
	}
	for _, tt := range tests {
		got := SanitizeQueryValue(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeQueryValue(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMapFieldFiltersSanitizesInjection(t *testing.T) {
	// Verify that MapFieldFilters sanitizes both keys and values.
	filters := map[string]string{
		"service":               "my-api",
		"field | delete":        "normal-value",
		"host":                  `value"; DROP TABLE`,
	}
	got := MapFieldFilters(filters, FieldMappingLoki)

	// "field | delete" → sanitized to "fielddelete", not in mapping, so passes through.
	if v, ok := got["fielddelete"]; !ok {
		t.Error("expected sanitized field name 'fielddelete' in result")
	} else if v != "normal-value" {
		t.Errorf("fielddelete = %q, want %q", v, "normal-value")
	}

	// host → mapped to "node", value sanitized.
	if v, ok := got["node"]; !ok {
		t.Error("expected 'node' in result (mapped from 'host')")
	} else if v != "value DROP TABLE" {
		t.Errorf("node = %q, want %q", v, "value DROP TABLE")
	}
}
