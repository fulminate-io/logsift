package reducer

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/fulminate-io/logsift"
)

func init() {
	logsift.RegisterConsolidator(&structuralConsolidator{})
}

type structuralConsolidator struct{}

func (s *structuralConsolidator) Name() string  { return "structural" }
func (s *structuralConsolidator) Priority() int { return 100 }

func (s *structuralConsolidator) Consolidate(clusters []logsift.Cluster) []logsift.Cluster {
	var fragments []*logsift.Cluster
	var normal []logsift.Cluster

	for i := range clusters {
		if isStructuralFragment(&clusters[i]) {
			fragments = append(fragments, &clusters[i])
		} else {
			normal = append(normal, clusters[i])
		}
	}

	if len(fragments) < 2 {
		return clusters
	}

	sort.Slice(fragments, func(i, j int) bool {
		return fragments[i].LastSeen.Before(fragments[j].LastSeen)
	})

	var groups [][]*logsift.Cluster
	currentGroup := []*logsift.Cluster{fragments[0]}

	for i := 1; i < len(fragments); i++ {
		prevEnd := currentGroup[len(currentGroup)-1].LastSeen
		if fragments[i].FirstSeen.Sub(prevEnd) <= 5*time.Second {
			currentGroup = append(currentGroup, fragments[i])
		} else {
			groups = append(groups, currentGroup)
			currentGroup = []*logsift.Cluster{fragments[i]}
		}
	}
	groups = append(groups, currentGroup)

	for _, group := range groups {
		if len(group) < 2 {
			for _, c := range group {
				normal = append(normal, *c)
			}
			continue
		}

		merged := logsift.Cluster{
			Template:  "Structural output (config dump / status report fragments)",
			Severity:  logsift.SeverityInfo,
			FirstSeen: group[0].FirstSeen,
			LastSeen:  group[0].LastSeen,
		}

		for _, c := range group {
			merged.Count += c.Count
			if c.FirstSeen.Before(merged.FirstSeen) {
				merged.FirstSeen = c.FirstSeen
			}
			if c.LastSeen.After(merged.LastSeen) {
				merged.LastSeen = c.LastSeen
			}
		}

		for _, c := range group {
			ex := c.Template
			if len(c.Examples) > 0 {
				ex = c.Examples[0]
			}
			if !isPunctuationOnly(strings.TrimSpace(ex)) && len(merged.Examples) < 2 {
				merged.Examples = append(merged.Examples, ex)
			}
		}
		if len(merged.Examples) == 0 && len(group[0].Examples) > 0 {
			merged.Examples = []string{group[0].Examples[0]}
		}

		normal = append(normal, merged)
	}

	return normal
}

var (
	reTreeChars       = regexp.MustCompile(`^[│├└─┬┤┘┐┌┼\s]+$`)
	reTreePrefix      = regexp.MustCompile(`^[│├└─┬┤┘┐┌┼]`)
	reJSONKeyFragment = regexp.MustCompile(`^\s*"[a-zA-Z_]\w*"\s*:\s*(\[\]|{})?\s*,?\s*$`)
	reWildcardHeavy   = regexp.MustCompile(`^(<\*>\s*){3,}$`)
	reServiceListing  = regexp.MustCompile(`^[\w._-]+\s+\((systemd|tail)\)$`)
	reJSONBlob        = regexp.MustCompile(`^\{"[a-zA-Z]`)
)

func isStructuralFragment(c *logsift.Cluster) bool {
	tpl := strings.TrimSpace(c.Template)
	return matchesStructuralPattern(tpl) ||
		isPunctuationOnly(tpl) ||
		slices.ContainsFunc(c.Examples, func(ex string) bool {
			return matchesStructuralPattern(strings.TrimSpace(ex))
		})
}

func matchesStructuralPattern(msg string) bool {
	return reTreeChars.MatchString(msg) ||
		reTreePrefix.MatchString(msg) ||
		reJSONKeyFragment.MatchString(msg) ||
		reWildcardHeavy.MatchString(msg) ||
		reServiceListing.MatchString(msg) ||
		isRawJSONBlob(msg)
}

// isRawJSONBlob detects JSON data dumps (e.g., S3 operations, timing data)
// that lack standard log message keys and are just structural data payloads.
func isRawJSONBlob(msg string) bool {
	if !reJSONBlob.MatchString(msg) {
		return false
	}
	// Don't treat as structural if it contains standard log message keys.
	for _, key := range []string{`"msg"`, `"message"`, `"level"`, `"error"`, `"event"`, `"severity"`} {
		if strings.Contains(msg, key) {
			return false
		}
	}
	return true
}

func isPunctuationOnly(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		switch r {
		case '[', ']', '{', '}', '(', ')', ',', ':', ';', '^', '~', '-', '_', '.', ' ', '\t',
			'│', '├', '└', '─', '┬', '┤', '┘', '┐', '┌', '┼':
			continue
		default:
			return false
		}
	}
	return true
}
