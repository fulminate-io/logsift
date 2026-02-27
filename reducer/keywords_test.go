package reducer

import (
	"testing"

	"github.com/fulminate-io/logsift"
)

func TestKeywordUpliftConsolidator(t *testing.T) {
	c := &keywordUpliftConsolidator{}

	t.Run("INFO with keyword becomes WARN", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "connection failed after retries", Severity: logsift.SeverityInfo, Count: 3},
		}
		result := c.Consolidate(clusters)
		if result[0].Severity != logsift.SeverityWarn {
			t.Errorf("expected WARN, got %s", result[0].Severity)
		}
	})

	t.Run("INFO without keyword stays INFO", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "processing request completed", Severity: logsift.SeverityInfo, Count: 3},
		}
		result := c.Consolidate(clusters)
		if result[0].Severity != logsift.SeverityInfo {
			t.Errorf("expected INFO, got %s", result[0].Severity)
		}
	})

	t.Run("WARN unmodified", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "some warning message", Severity: logsift.SeverityWarn, Count: 1},
		}
		result := c.Consolidate(clusters)
		if result[0].Severity != logsift.SeverityWarn {
			t.Errorf("expected WARN, got %s", result[0].Severity)
		}
	})

	t.Run("ERROR unmodified", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "some error without keywords", Severity: logsift.SeverityError, Count: 1},
		}
		result := c.Consolidate(clusters)
		if result[0].Severity != logsift.SeverityError {
			t.Errorf("expected ERROR, got %s", result[0].Severity)
		}
	})

	t.Run("keyword in example only triggers WARN", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{
				Template: "request to <*> returned <*>",
				Severity: logsift.SeverityInfo,
				Count:    5,
				Examples: []string{"request to /api/v1/users returned timeout"},
			},
		}
		result := c.Consolidate(clusters)
		if result[0].Severity != logsift.SeverityWarn {
			t.Errorf("expected WARN from example keyword, got %s", result[0].Severity)
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "request TIMEOUT after 30s", Severity: logsift.SeverityInfo, Count: 1},
		}
		result := c.Consolidate(clusters)
		if result[0].Severity != logsift.SeverityWarn {
			t.Errorf("expected WARN for case-insensitive match, got %s", result[0].Severity)
		}
	})

	t.Run("word boundary: error_count does NOT match", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "metric error_count incremented", Severity: logsift.SeverityInfo, Count: 1},
		}
		result := c.Consolidate(clusters)
		if result[0].Severity != logsift.SeverityInfo {
			t.Errorf("error_count should not trigger uplift, got %s", result[0].Severity)
		}
	})

	t.Run("word boundary: error: does match", func(t *testing.T) {
		clusters := []logsift.Cluster{
			{Template: "error: something went wrong", Severity: logsift.SeverityInfo, Count: 1},
		}
		result := c.Consolidate(clusters)
		if result[0].Severity != logsift.SeverityWarn {
			t.Errorf("expected WARN for 'error:', got %s", result[0].Severity)
		}
	})
}

func TestKeywordIndividual(t *testing.T) {
	c := &keywordUpliftConsolidator{}

	keywords := []string{
		"failed",
		"timeout",
		"denied",
		"panic",
		"exception",
		"crashed",
		"fatal",
		"rejected",
		"unavailable",
		"exceeded",
		"overflow",
		"corrupted",
		"aborted",
		"broken",
		"violation",
	}

	for _, kw := range keywords {
		t.Run(kw, func(t *testing.T) {
			clusters := []logsift.Cluster{
				{Template: "something " + kw + " happened", Severity: logsift.SeverityInfo, Count: 1},
			}
			result := c.Consolidate(clusters)
			if result[0].Severity != logsift.SeverityWarn {
				t.Errorf("keyword %q should trigger uplift, got %s", kw, result[0].Severity)
			}
		})
	}
}
