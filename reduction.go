package logsift

import (
	"crypto/sha256"
	"sort"
	"sync"
	"time"
)

// Consolidator merges language-specific or structural noise fragments into
// coherent clusters. Each consolidator targets a specific pattern family
// (e.g., Go stack dumps, Python tracebacks, config fragments).
//
// Consolidators are registered via init() in their respective files and
// executed in priority order during the reduction pipeline.
type Consolidator interface {
	Name() string
	Priority() int
	Consolidate(clusters []Cluster) []Cluster
}

var (
	consolidatorMu      sync.Mutex
	consolidators       []Consolidator
	consolidatorsSorted bool
)

// RegisterConsolidator adds a consolidator to the pipeline. Called from init().
func RegisterConsolidator(c Consolidator) {
	consolidatorMu.Lock()
	defer consolidatorMu.Unlock()
	consolidators = append(consolidators, c)
	consolidatorsSorted = false
}

func getConsolidators() []Consolidator {
	consolidatorMu.Lock()
	defer consolidatorMu.Unlock()
	if !consolidatorsSorted {
		sort.Slice(consolidators, func(i, j int) bool {
			return consolidators[i].Priority() < consolidators[j].Priority()
		})
		consolidatorsSorted = true
	}
	result := make([]Consolidator, len(consolidators))
	copy(result, consolidators)
	return result
}

// ReductionOpts configures the context reduction pipeline.
type ReductionOpts struct {
	SeverityMin string
	TokenBudget int
	Cursor      *PaginationCursor
}

// DefaultTokenBudget is the default token budget for search results.
const DefaultTokenBudget = 4000

// Reduce runs the full context reduction pipeline on raw log entries:
//
//  1. Severity filtering - drop entries below SeverityMin
//  2. Exact deduplication - hash-based fast-path pre-filter for Drain
//  3. Drain template clustering
//  4. Registered consolidators (Go stack, Python traceback, structural, etc.)
//  5. Stack trace grouping
//  6. Signal-first sorting (severity DESC, count bucket DESC, last_seen DESC)
//  7. Token-budget truncation with cursor
func Reduce(entries []LogEntry, opts ReductionOpts) *ReductionResult {
	if opts.SeverityMin == "" {
		opts.SeverityMin = SeverityInfo
	}
	if opts.TokenBudget <= 0 {
		opts.TokenBudget = DefaultTokenBudget
	}

	rawCount := len(entries)

	// Layer 1: Severity filtering
	entries = filterBySeverity(entries, opts.SeverityMin)

	// Layer 2: Exact deduplication (fast-path pre-filter for Drain)
	dedupEntries := exactDedup(entries)

	// Layer 3: Drain template clustering
	clusters := drainCluster2(dedupEntries)

	// Layer 4: Registered consolidators (ordered by priority)
	for _, c := range getConsolidators() {
		clusters = c.Consolidate(clusters)
	}

	// Layer 5: Stack trace grouping
	clusters = groupStackTraces(clusters)

	// Layer 6: Signal-first sorting
	sortClusters(clusters)

	// Apply cursor offset if resuming
	clusterOffset := 0
	if opts.Cursor != nil {
		clusterOffset = opts.Cursor.ClusterOffset
	}
	if clusterOffset > len(clusters) {
		clusterOffset = len(clusters)
	}
	clusters = clusters[clusterOffset:]

	// Layer 7: Token-budget truncation
	truncated, tokensUsed, hasMore := truncateToBudget(clusters, opts.TokenBudget)

	return &ReductionResult{
		Clusters:   truncated,
		RawCount:   rawCount,
		TokensUsed: tokensUsed,
		HasMore:    hasMore,
	}
}

func filterBySeverity(entries []LogEntry, minSeverity string) []LogEntry {
	if minSeverity == SeverityTrace {
		return entries
	}
	filtered := make([]LogEntry, 0, len(entries))
	for i := range entries {
		if SeverityAtLeast(entries[i].Severity, minSeverity) {
			filtered = append(filtered, entries[i])
		}
	}
	return filtered
}

type dedupEntry struct {
	LogEntry
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

func exactDedup(entries []LogEntry) []dedupEntry {
	type dedupKey struct {
		severity string
		hash     [32]byte
	}

	groups := make(map[dedupKey]*dedupEntry)
	var order []dedupKey

	for i := range entries {
		e := &entries[i]
		stripped := stripVariableTokens(e.Message)
		h := sha256.Sum256([]byte(e.Severity + "|" + stripped))
		key := dedupKey{severity: e.Severity, hash: h}

		if existing, ok := groups[key]; ok {
			existing.Count++
			if e.Timestamp.Before(existing.FirstSeen) {
				existing.FirstSeen = e.Timestamp
			}
			if e.Timestamp.After(existing.LastSeen) {
				existing.LastSeen = e.Timestamp
			}
		} else {
			de := &dedupEntry{
				LogEntry:  *e,
				Count:     1,
				FirstSeen: e.Timestamp,
				LastSeen:  e.Timestamp,
			}
			groups[key] = de
			order = append(order, key)
		}
	}

	result := make([]dedupEntry, 0, len(order))
	for _, key := range order {
		result = append(result, *groups[key])
	}
	return result
}

func stripVariableTokens(msg string) string {
	msg = reTimestamp.ReplaceAllString(msg, "")
	msg = reUUID.ReplaceAllString(msg, "")
	msg = reIPv4.ReplaceAllString(msg, "")
	return msg
}

func drainCluster2(entries []dedupEntry) []Cluster {
	engine := newDrainEngine()

	clusterMap := make(map[*drainCluster]*Cluster)

	for i := range entries {
		e := &entries[i]
		dc := engine.AddMessage(e.Message)
		if dc == nil {
			continue
		}

		if c, ok := clusterMap[dc]; ok {
			c.Count += e.Count
			if e.FirstSeen.Before(c.FirstSeen) {
				c.FirstSeen = e.FirstSeen
			}
			if e.LastSeen.After(c.LastSeen) {
				c.LastSeen = e.LastSeen
			}
			if len(c.Examples) < 2 {
				c.Examples = append(c.Examples, e.Message)
			}
			if severityOrder[e.Severity] > severityOrder[c.Severity] {
				c.Severity = e.Severity
			}
		} else {
			c := &Cluster{
				Template:  dc.template,
				Severity:  e.Severity,
				Count:     e.Count,
				FirstSeen: e.FirstSeen,
				LastSeen:  e.LastSeen,
				Examples:  []string{e.Message},
			}
			clusterMap[dc] = c
		}
	}

	for dc, c := range clusterMap {
		c.Template = dc.template
	}

	result := make([]Cluster, 0, len(clusterMap))
	for _, c := range clusterMap {
		result = append(result, *c)
	}
	return result
}

func countBucket(count int) int {
	switch {
	case count <= 1:
		return 4
	case count <= 5:
		return 3
	case count <= 50:
		return 2
	default:
		return 1
	}
}

func sortClusters(clusters []Cluster) {
	sort.Slice(clusters, func(i, j int) bool {
		si := severityOrder[clusters[i].Severity]
		sj := severityOrder[clusters[j].Severity]
		if si != sj {
			return si > sj
		}
		bi := countBucket(clusters[i].Count)
		bj := countBucket(clusters[j].Count)
		if bi != bj {
			return bi > bj
		}
		return clusters[i].LastSeen.After(clusters[j].LastSeen)
	})
}

func truncateToBudget(clusters []Cluster, budget int) ([]Cluster, int, bool) {
	headerBudget := 100
	footerBudget := 60

	var result []Cluster
	tokensUsed := headerBudget

	for i := range clusters {
		c := &clusters[i]
		clusterTokens := estimateClusterTokens(c)
		if tokensUsed+clusterTokens > budget-footerBudget && len(result) > 0 {
			return result, tokensUsed + footerBudget, true
		}
		result = append(result, *c)
		tokensUsed += clusterTokens
	}

	return result, tokensUsed, false
}

func estimateClusterTokens(c *Cluster) int {
	chars := len(c.Template) + 40
	for _, ex := range c.Examples {
		chars += len(ex) + 20
	}
	return (chars + 3) / 4
}

// TruncateStr truncates a string to maxLen, appending "..." if truncated.
func TruncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
