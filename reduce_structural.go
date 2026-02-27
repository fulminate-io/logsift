package logsift

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

// Stack trace detection patterns (shared across consolidators).
var (
	ReJavaStack       = regexp.MustCompile(`^\s+at\s+`)
	RePythonStack     = regexp.MustCompile(`^\s+File\s+"`)
	ReGoStack         = regexp.MustCompile(`^goroutine\s+\d+`)
	ReExceptionHeader = regexp.MustCompile(
		`(?i)^(exception|error|panic|traceback|caused by|fatal)`)
)

func groupStackTraces(clusters []Cluster) []Cluster {
	var stackClusters []Cluster
	var normalClusters []Cluster

	for i := range clusters {
		c := &clusters[i]
		if isStackTrace(c.Template) || isStackTrace(strings.Join(c.Examples, "\n")) {
			stackClusters = append(stackClusters, *c)
		} else {
			normalClusters = append(normalClusters, *c)
		}
	}

	if len(stackClusters) == 0 {
		return clusters
	}

	type stackGroup struct {
		hash    string
		cluster Cluster
	}
	groups := make(map[string]*stackGroup)
	var groupOrder []string

	for i := range stackClusters {
		sc := &stackClusters[i]
		h := stackTraceHash(sc.Template, sc.Examples)
		if g, ok := groups[h]; ok {
			g.cluster.Count += sc.Count
			if sc.FirstSeen.Before(g.cluster.FirstSeen) {
				g.cluster.FirstSeen = sc.FirstSeen
			}
			if sc.LastSeen.After(g.cluster.LastSeen) {
				g.cluster.LastSeen = sc.LastSeen
			}
		} else {
			groups[h] = &stackGroup{
				hash:    h,
				cluster: *sc,
			}
			groupOrder = append(groupOrder, h)
		}
	}

	for _, h := range groupOrder {
		normalClusters = append(normalClusters, groups[h].cluster)
	}
	return normalClusters
}

func isStackTrace(msg string) bool {
	for _, line := range strings.Split(msg, "\n") {
		if ReJavaStack.MatchString(line) ||
			RePythonStack.MatchString(line) ||
			ReGoStack.MatchString(line) ||
			strings.HasPrefix(line, "Traceback") {
			return true
		}
	}
	return false
}

func stackTraceHash(template string, examples []string) string {
	text := template
	if len(examples) > 0 {
		text = examples[0]
	}

	lines := strings.Split(text, "\n")
	var keyParts []string

	for _, line := range lines {
		if ReExceptionHeader.MatchString(line) {
			keyParts = append(keyParts, strings.TrimSpace(line))
			break
		}
	}

	frameCount := 0
	for _, line := range lines {
		if ReJavaStack.MatchString(line) || RePythonStack.MatchString(line) {
			keyParts = append(keyParts, strings.TrimSpace(line))
			frameCount++
			if frameCount >= 3 {
				break
			}
		}
	}

	h := sha256.Sum256([]byte(strings.Join(keyParts, "|")))
	return fmt.Sprintf("%x", h[:8])
}
