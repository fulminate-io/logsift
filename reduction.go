package logsift

import (
	"crypto/sha256"
	"regexp"
	"sort"
	"strings"
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

	// Per-call tuning.
	SuppressPatterns []*regexp.Regexp // Clusters matching these are treated as noise
	SeverityKeywords []string         // Extra words that trigger INFO→WARN uplift
	NoiseThreshold   int              // Min count to consider a cluster noise (0=auto)
}

// DefaultTokenBudget is the default token budget for search results.
const DefaultTokenBudget = 4000

// Reduce runs the full context reduction pipeline on raw log entries:
//
//  1. Severity filtering - drop entries below SeverityMin
//  2. Exact deduplication - hash-based fast-path pre-filter for Drain
//  3. Drain template clustering
//  4. Registered consolidators (keyword uplift, Python traceback, structural, etc.)
//  5. Stack trace grouping
//  5b. User severity keyword uplift (if configured)
//  6. Signal-first sorting (severity DESC, count bucket DESC, last_seen DESC)
//  6b. Noise compression - demote high-freq low-signal clusters to end
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

	// Layer 5b: User severity keyword uplift
	if len(opts.SeverityKeywords) > 0 {
		clusters = applySeverityKeywords(clusters, opts.SeverityKeywords)
	}

	// Layer 6: Signal-first sorting
	sortClusters(clusters)

	// Layer 6b: Noise compression — demote high-freq low-signal clusters
	clusters = compressNoise(clusters, opts)

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
		Clusters:    truncated,
		RawCount:    rawCount,
		TokensUsed:  tokensUsed,
		TokenBudget: opts.TokenBudget,
		HasMore:     hasMore,
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
				c.Examples = append(c.Examples, TruncateStr(e.Message, maxExampleLen))
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
				Examples:  []string{TruncateStr(e.Message, maxExampleLen)},
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

// maxExampleLen is the maximum length for stored cluster examples.
// Matches the truncation applied during display formatting.
const maxExampleLen = 200

func estimateClusterTokens(c *Cluster) int {
	tplLen := len(c.Template)
	if tplLen > maxExampleLen {
		tplLen = maxExampleLen
	}
	chars := tplLen + 40
	for _, ex := range c.Examples {
		exLen := len(ex)
		if exLen > maxExampleLen {
			exLen = maxExampleLen
		}
		chars += exLen + 20
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

// applySeverityKeywords uplifts INFO clusters to WARN if their template
// contains any of the user-provided keywords.
func applySeverityKeywords(clusters []Cluster, keywords []string) []Cluster {
	for i := range clusters {
		if clusters[i].Severity != SeverityInfo {
			continue
		}
		tplLower := strings.ToLower(clusters[i].Template)
		for _, kw := range keywords {
			if strings.Contains(tplLower, strings.ToLower(kw)) {
				clusters[i].Severity = SeverityWarn
				break
			}
		}
	}
	return clusters
}

// compressNoise moves high-frequency, low-signal clusters to the end
// and strips their examples to save token budget.
//
// A cluster is noise if:
//   - severity is INFO or DEBUG
//   - count exceeds the noise threshold (auto-detected or user-configured)
//   - template has ≤ 5 words (short/generic message)
//   - template contains no negative sentiment words
//   - OR template matches a user-provided suppress pattern
func compressNoise(clusters []Cluster, opts ReductionOpts) []Cluster {
	if len(clusters) < 3 {
		return clusters
	}

	threshold := detectNoiseThreshold(clusters, opts.NoiseThreshold)

	var signal, noise []Cluster
	for i := range clusters {
		if isNoiseCluster(&clusters[i], threshold, opts.SuppressPatterns) {
			// Strip examples from noise clusters to save tokens.
			clusters[i].Examples = nil
			noise = append(noise, clusters[i])
		} else {
			signal = append(signal, clusters[i])
		}
	}

	if len(noise) == 0 {
		return clusters
	}

	// Signal clusters first, noise at the end.
	return append(signal, noise...)
}

func detectNoiseThreshold(clusters []Cluster, userThreshold int) int {
	if userThreshold > 0 {
		return userThreshold
	}

	// Auto-detect: noise threshold = 10x median count of INFO clusters.
	var infoCounts []int
	for _, c := range clusters {
		if c.Severity == SeverityInfo || c.Severity == SeverityDebug {
			infoCounts = append(infoCounts, c.Count)
		}
	}
	if len(infoCounts) < 5 {
		return 0 // not enough data, don't compress
	}
	sort.Ints(infoCounts)
	median := infoCounts[len(infoCounts)/2]
	threshold := median * 10
	if threshold < 50 {
		threshold = 50
	}
	return threshold
}

// reNegativeSentiment matches universal failure/problem indicators in log messages.
var reNegativeSentiment = regexp.MustCompile(
	`(?i)\b(fail(?:ed|ure|ing)?|error(?:ed|s)?|timeout|timed\s+out|refused|denied|` +
		`panic(?:ked)?|crash(?:ed)?|fatal|exception|rejected|unavailable|exceeded|` +
		`overflow|corrupt(?:ed|ion)?|abort(?:ed)?|broken|violation)\b`)

func isNoiseCluster(c *Cluster, threshold int, suppressPatterns []*regexp.Regexp) bool {
	// Check suppress patterns first — these always classify as noise.
	for _, p := range suppressPatterns {
		if p.MatchString(c.Template) {
			return true
		}
	}

	// Statistical noise detection.
	if threshold <= 0 {
		return false
	}
	if c.Severity != SeverityInfo && c.Severity != SeverityDebug {
		return false
	}
	if c.Count < threshold {
		return false
	}
	words := len(strings.Fields(c.Template))
	if words > 5 {
		return false
	}
	if reNegativeSentiment.MatchString(c.Template) {
		return false
	}
	return true
}
