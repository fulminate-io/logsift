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
			name:    "elastic mapping",
			filters: map[string]string{"service": "api", "namespace": "production"},
			mapping: FieldMappingElastic,
			expected: map[string]string{
				"service.name":         "api",
				"kubernetes.namespace": "production",
			},
		},
		{
			name:    "unknown fields pass through",
			filters: map[string]string{"service": "api", "custom_field": "value"},
			mapping: FieldMappingDatadog,
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
