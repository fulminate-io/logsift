package logsift

import (
	"testing"
	"time"
)

func TestFilterBySeverity(t *testing.T) {
	now := time.Now()
	entries := []LogEntry{
		{Timestamp: now, Severity: SeverityTrace, Message: "trace msg"},
		{Timestamp: now, Severity: SeverityDebug, Message: "debug msg"},
		{Timestamp: now, Severity: SeverityInfo, Message: "info msg"},
		{Timestamp: now, Severity: SeverityWarn, Message: "warn msg"},
		{Timestamp: now, Severity: SeverityError, Message: "error msg"},
		{Timestamp: now, Severity: SeverityCritical, Message: "critical msg"},
	}

	tests := []struct {
		minSev   string
		expected int
	}{
		{SeverityTrace, 6},
		{SeverityDebug, 5},
		{SeverityInfo, 4},
		{SeverityWarn, 3},
		{SeverityError, 2},
		{SeverityCritical, 1},
	}

	for _, tt := range tests {
		t.Run("min_"+tt.minSev, func(t *testing.T) {
			result := filterBySeverity(entries, tt.minSev)
			if len(result) != tt.expected {
				t.Errorf("filterBySeverity(min=%s): got %d entries, want %d", tt.minSev, len(result), tt.expected)
			}
		})
	}
}

func TestExactDedup(t *testing.T) {
	now := time.Now()
	entries := []LogEntry{
		{Timestamp: now, Severity: SeverityInfo, Message: "health check OK"},
		{Timestamp: now.Add(1 * time.Second), Severity: SeverityInfo, Message: "health check OK"},
		{Timestamp: now.Add(2 * time.Second), Severity: SeverityInfo, Message: "health check OK"},
		{Timestamp: now.Add(3 * time.Second), Severity: SeverityError, Message: "connection timeout"},
		{Timestamp: now.Add(4 * time.Second), Severity: SeverityError, Message: "connection timeout"},
	}

	result := exactDedup(entries)

	if len(result) != 2 {
		t.Fatalf("expected 2 deduped entries, got %d", len(result))
	}

	if result[0].Count != 3 {
		t.Errorf("health check count: got %d, want 3", result[0].Count)
	}
	if !result[0].FirstSeen.Equal(now) {
		t.Errorf("first seen should be %v, got %v", now, result[0].FirstSeen)
	}
	if !result[0].LastSeen.Equal(now.Add(2 * time.Second)) {
		t.Errorf("last seen should be %v, got %v", now.Add(2*time.Second), result[0].LastSeen)
	}

	if result[1].Count != 2 {
		t.Errorf("connection timeout count: got %d, want 2", result[1].Count)
	}
}

func TestReduce_FullPipeline(t *testing.T) {
	now := time.Now()

	var entries []LogEntry
	for i := range 100 {
		entries = append(entries, LogEntry{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Severity:  SeverityInfo,
			Message:   "GET /api/health HTTP/1.1 200 12ms",
		})
	}
	for i := range 5 {
		entries = append(entries, LogEntry{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Severity:  SeverityError,
			Message:   "database connection timeout after 3200ms",
		})
	}
	entries = append(entries, LogEntry{
		Timestamp: now,
		Severity:  SeverityCritical,
		Message:   "PANIC: nil pointer dereference in handler processOrder",
	})
	for i := range 50 {
		entries = append(entries, LogEntry{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Severity:  SeverityDebug,
			Message:   "processing request",
		})
	}

	result := Reduce(entries, ReductionOpts{
		SeverityMin: SeverityInfo,
		TokenBudget: 4000,
	})

	if result.RawCount != 156 {
		t.Errorf("raw count: got %d, want 156", result.RawCount)
	}

	if len(result.Clusters) == 0 {
		t.Fatal("expected at least 1 cluster")
	}

	if result.Clusters[0].Severity != SeverityCritical {
		t.Errorf("first cluster severity: got %s, want %s", result.Clusters[0].Severity, SeverityCritical)
	}
}

func TestSortClusters(t *testing.T) {
	now := time.Now()

	t.Run("severity ordering", func(t *testing.T) {
		clusters := []Cluster{
			{Severity: SeverityInfo, Count: 1, LastSeen: now},
			{Severity: SeverityCritical, Count: 1, LastSeen: now},
			{Severity: SeverityError, Count: 1, LastSeen: now},
			{Severity: SeverityWarn, Count: 1, LastSeen: now},
		}

		sortClusters(clusters)

		expected := []string{SeverityCritical, SeverityError, SeverityWarn, SeverityInfo}
		for i, c := range clusters {
			if c.Severity != expected[i] {
				t.Errorf("cluster[%d]: got severity %s, want %s", i, c.Severity, expected[i])
			}
		}
	})

	t.Run("count bucket ordering within same severity", func(t *testing.T) {
		clusters := []Cluster{
			{Severity: SeverityError, Count: 100, LastSeen: now},
			{Severity: SeverityError, Count: 1, LastSeen: now},
			{Severity: SeverityError, Count: 20, LastSeen: now},
			{Severity: SeverityError, Count: 3, LastSeen: now},
		}

		sortClusters(clusters)

		expectedCounts := []int{1, 3, 20, 100}
		for i, c := range clusters {
			if c.Count != expectedCounts[i] {
				t.Errorf("cluster[%d]: got count %d, want %d", i, c.Count, expectedCounts[i])
			}
		}
	})

	t.Run("recency within same bucket", func(t *testing.T) {
		clusters := []Cluster{
			{Severity: SeverityError, Count: 1, LastSeen: now.Add(-10 * time.Minute)},
			{Severity: SeverityError, Count: 1, LastSeen: now},
			{Severity: SeverityError, Count: 1, LastSeen: now.Add(-5 * time.Minute)},
		}

		sortClusters(clusters)

		if !clusters[0].LastSeen.Equal(now) {
			t.Errorf("first cluster should be most recent")
		}
	})
}

func TestCountBucket(t *testing.T) {
	tests := []struct {
		count    int
		expected int
	}{
		{0, 4}, {1, 4},
		{2, 3}, {5, 3},
		{6, 2}, {50, 2},
		{51, 1}, {1000, 1},
	}

	for _, tt := range tests {
		if got := countBucket(tt.count); got != tt.expected {
			t.Errorf("countBucket(%d) = %d, want %d", tt.count, got, tt.expected)
		}
	}
}

func TestTruncateToBudget(t *testing.T) {
	clusters := make([]Cluster, 100)
	for i := range clusters {
		clusters[i] = Cluster{
			Template: "This is a template message with some content to take up space in the token budget calculation",
			Severity: SeverityInfo,
			Count:    1,
			Examples: []string{"Example message that is realistic for a log entry"},
		}
	}

	result, tokensUsed, hasMore := truncateToBudget(clusters, 500)

	if !hasMore {
		t.Error("expected hasMore=true for 100 clusters with 500 token budget")
	}
	if len(result) >= 100 {
		t.Error("expected truncation to fewer than 100 clusters")
	}
	if tokensUsed > 500 {
		t.Errorf("tokens used (%d) exceeds budget (500)", tokensUsed)
	}
}
