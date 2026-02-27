package logsift

import (
	"testing"
)

func TestDrainEngine_BasicClustering(t *testing.T) {
	engine := newDrainEngine()

	// Add similar messages that should cluster together
	msgs := []string{
		"GET /api/users/123 HTTP/1.1 200 45ms",
		"GET /api/users/456 HTTP/1.1 200 32ms",
		"GET /api/users/789 HTTP/1.1 200 67ms",
	}

	for _, msg := range msgs {
		engine.AddMessage(msg)
	}

	clusters := engine.Clusters()
	if len(clusters) != 1 {
		t.Errorf("expected 1 cluster for similar GET requests, got %d", len(clusters))
		for i, c := range clusters {
			t.Logf("  cluster %d: template=%q count=%d", i, c.template, c.count)
		}
		return
	}

	if clusters[0].count != 3 {
		t.Errorf("expected count 3, got %d", clusters[0].count)
	}
}

func TestDrainEngine_DifferentPatterns(t *testing.T) {
	engine := newDrainEngine()

	// Add messages with different patterns
	engine.AddMessage("database connection timeout after 3200ms")
	engine.AddMessage("database connection timeout after 5100ms")
	engine.AddMessage("GET /api/health HTTP/1.1 200 12ms")
	engine.AddMessage("GET /api/health HTTP/1.1 200 8ms")
	engine.AddMessage("PANIC: nil pointer dereference in handler processOrder")

	clusters := engine.Clusters()
	if len(clusters) < 2 || len(clusters) > 4 {
		t.Errorf("expected 2-4 clusters for different patterns, got %d", len(clusters))
		for i, c := range clusters {
			t.Logf("  cluster %d: template=%q count=%d", i, c.template, c.count)
		}
	}
}

func TestDrainEngine_PreProcess(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // should contain <*> for variable parts
	}{
		{
			name:  "UUID replacement",
			input: "Request 550e8400-e29b-41d4-a716-446655440000 failed",
			want:  "Request <*> failed",
		},
		{
			name:  "IPv4 replacement",
			input: "Connection from 192.168.1.100 refused",
			want:  "Connection from <*> refused",
		},
		{
			name:  "timestamp replacement",
			input: "2026-02-26T10:30:00Z error occurred",
			want:  "<*> error occurred",
		},
		{
			name:  "long numeric replacement",
			input: "Request ID 1234567890 processed",
			want:  "Request ID <*> processed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := preProcess(tt.input)
			if got != tt.want {
				t.Errorf("preProcess(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDrainEngine_Similarity(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want float64
	}{
		{
			name: "identical",
			a:    []string{"GET", "/api", "200"},
			b:    []string{"GET", "/api", "200"},
			want: 1.0,
		},
		{
			name: "one difference",
			a:    []string{"GET", "/api", "200"},
			b:    []string{"GET", "/api", "404"},
			want: 2.0 / 3.0,
		},
		{
			name: "all different",
			a:    []string{"GET", "/api", "200"},
			b:    []string{"POST", "/users", "500"},
			want: 0.0,
		},
		{
			name: "wildcards match",
			a:    []string{"GET", "<*>", "200"},
			b:    []string{"GET", "/api", "200"},
			want: 1.0,
		},
		{
			name: "different lengths",
			a:    []string{"GET", "/api"},
			b:    []string{"GET", "/api", "200"},
			want: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := similarity(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("similarity(%v, %v) = %f, want %f", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestDrainEngine_MergeTokens(t *testing.T) {
	template := []string{"GET", "/api/users", "<*>", "200"}
	tokens := []string{"GET", "/api/users", "789", "200"}

	result := mergeTokens(template, tokens)
	expected := []string{"GET", "/api/users", "<*>", "200"}

	if len(result) != len(expected) {
		t.Fatalf("expected %d tokens, got %d", len(expected), len(result))
	}
	for i := range result {
		if result[i] != expected[i] {
			t.Errorf("token[%d]: got %q, want %q", i, result[i], expected[i])
		}
	}
}

func TestDrainEngine_EmptyMessage(t *testing.T) {
	engine := newDrainEngine()
	result := engine.AddMessage("")
	if result != nil {
		t.Error("expected nil for empty message")
	}
}

func TestDrainEngine_MaxClusters(t *testing.T) {
	engine := newDrainEngine()

	// Add many unique messages to hit the cluster limit
	for i := range drainMaxClusters + 50 {
		engine.AddMessage("unique_pattern_" + string(rune('A'+i%26)) + "_" + string(rune('a'+i/26%26)))
	}

	// Should not panic or error — either clusters are capped or fallback works
	clusters := engine.Clusters()
	if len(clusters) == 0 {
		t.Error("expected at least 1 cluster")
	}
}
