package logsift

import (
	"regexp"
	"strings"
)

// Drain parameters.
const (
	drainSimThreshold = 0.4
	drainMaxDepth     = 4
	drainMaxChildren  = 100
	drainMaxClusters  = 200
)

// drainEngine implements the Drain log parsing algorithm.
// This is an in-memory, per-search-call implementation — no persistence needed.
//
// Algorithm overview:
//  1. Pre-process: strip timestamps and high-cardinality tokens (UUIDs, IPs, request IDs)
//  2. Fixed-depth prefix parse tree (depth=4)
//  3. Token-count branching at level 1
//  4. Prefix-token branching at levels 2-N
//  5. Similarity scoring at leaf nodes (threshold=0.4)
//  6. Template merging: replace differing tokens with <*>
type drainEngine struct {
	root     *drainNode
	clusters []*drainCluster
}

type drainNode struct {
	children map[string]*drainNode
	clusters []*drainCluster
}

type drainCluster struct {
	tokens   []string
	template string
	count    int
}

// Regex patterns for pre-processing.
var (
	reTimestamp = regexp.MustCompile(
		`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?` +
			`|\d{2}:\d{2}:\d{2}(?:\.\d+)?` +
			`|\d{10,13}`)

	reUUID    = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reIPv4    = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reHexID   = regexp.MustCompile(`\b[0-9a-fA-F]{16,}\b`)
	reNumeric = regexp.MustCompile(`\b\d{4,}\b`)
)

const drainWildcard = "<*>"

func newDrainEngine() *drainEngine {
	return &drainEngine{
		root: &drainNode{
			children: make(map[string]*drainNode),
		},
	}
}

func preProcess(msg string) string {
	msg = reUUID.ReplaceAllString(msg, drainWildcard)
	msg = reTimestamp.ReplaceAllString(msg, drainWildcard)
	msg = reIPv4.ReplaceAllString(msg, drainWildcard)
	msg = reHexID.ReplaceAllString(msg, drainWildcard)
	msg = reNumeric.ReplaceAllString(msg, drainWildcard)
	return msg
}

func tokenize(msg string) []string {
	return strings.Fields(msg)
}

func (d *drainEngine) AddMessage(msg string) *drainCluster {
	processed := preProcess(msg)
	tokens := tokenize(processed)
	if len(tokens) == 0 {
		return nil
	}

	tokenCountKey := tokenCountBucket(len(tokens))
	child := d.getOrCreateChild(d.root, tokenCountKey)

	node := child
	for depth := 0; depth < drainMaxDepth-1 && depth < len(tokens); depth++ {
		token := tokens[depth]
		if isWildcard(token) {
			token = drainWildcard
		}
		node = d.getOrCreateChild(node, token)
	}

	cluster := d.findMatchingCluster(node, tokens)
	if cluster != nil {
		cluster.count++
		cluster.tokens = mergeTokens(cluster.tokens, tokens)
		cluster.template = strings.Join(cluster.tokens, " ")
		return cluster
	}

	if len(d.clusters) >= drainMaxClusters {
		best := d.findBestGlobalMatch(tokens)
		if best != nil {
			best.count++
			best.tokens = mergeTokens(best.tokens, tokens)
			best.template = strings.Join(best.tokens, " ")
			return best
		}
		c := &drainCluster{
			tokens:   tokens,
			template: strings.Join(tokens, " "),
			count:    1,
		}
		d.clusters = append(d.clusters, c)
		return c
	}

	c := &drainCluster{
		tokens:   tokens,
		template: strings.Join(tokens, " "),
		count:    1,
	}
	node.clusters = append(node.clusters, c)
	d.clusters = append(d.clusters, c)
	return c
}

func (d *drainEngine) getOrCreateChild(parent *drainNode, key string) *drainNode {
	if child, ok := parent.children[key]; ok {
		return child
	}
	if len(parent.children) >= drainMaxChildren {
		if child, ok := parent.children[drainWildcard]; ok {
			return child
		}
		key = drainWildcard
	}
	child := &drainNode{
		children: make(map[string]*drainNode),
	}
	parent.children[key] = child
	return child
}

func (d *drainEngine) findMatchingCluster(node *drainNode, tokens []string) *drainCluster {
	var bestCluster *drainCluster
	bestSim := drainSimThreshold

	for _, c := range node.clusters {
		sim := similarity(c.tokens, tokens)
		if sim > bestSim {
			bestSim = sim
			bestCluster = c
		}
	}
	return bestCluster
}

func (d *drainEngine) findBestGlobalMatch(tokens []string) *drainCluster {
	var bestCluster *drainCluster
	bestSim := drainSimThreshold

	for _, c := range d.clusters {
		if len(c.tokens) != len(tokens) {
			continue
		}
		sim := similarity(c.tokens, tokens)
		if sim > bestSim {
			bestSim = sim
			bestCluster = c
		}
	}
	return bestCluster
}

func similarity(a, b []string) float64 {
	if len(a) != len(b) {
		return 0
	}
	if len(a) == 0 {
		return 0
	}

	matches := 0
	for i := range a {
		if a[i] == b[i] || a[i] == drainWildcard || b[i] == drainWildcard {
			matches++
		}
	}
	return float64(matches) / float64(len(a))
}

func mergeTokens(template, tokens []string) []string {
	if len(template) != len(tokens) {
		return template
	}
	result := make([]string, len(template))
	for i := range template {
		if template[i] == tokens[i] || tokens[i] == drainWildcard {
			result[i] = template[i]
		} else if template[i] == drainWildcard {
			result[i] = drainWildcard
		} else {
			result[i] = drainWildcard
		}
	}
	return result
}

func tokenCountBucket(n int) string {
	switch {
	case n <= 3:
		return "short"
	case n <= 8:
		return "medium"
	case n <= 15:
		return "long"
	default:
		return "vlong"
	}
}

func isWildcard(token string) bool {
	if token == drainWildcard {
		return true
	}
	return containsDigit(token)
}

func containsDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func (d *drainEngine) Clusters() []*drainCluster {
	return d.clusters
}
