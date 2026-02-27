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
	logsift.RegisterConsolidator(&pythonTracebackConsolidator{})
}

type pythonTracebackConsolidator struct{}

func (p *pythonTracebackConsolidator) Name() string  { return "python_traceback" }
func (p *pythonTracebackConsolidator) Priority() int { return 20 }

func (p *pythonTracebackConsolidator) Consolidate(clusters []logsift.Cluster) []logsift.Cluster {
	var fragments []*logsift.Cluster
	var tracebackHeaders []*logsift.Cluster
	var normal []logsift.Cluster

	for i := range clusters {
		c := &clusters[i]
		tpl := c.Template
		if len(c.Examples) > 0 {
			tpl = c.Examples[0]
		}
		if strings.HasPrefix(strings.TrimSpace(tpl), "Traceback (most recent call last)") {
			tracebackHeaders = append(tracebackHeaders, c)
		} else if isPythonTracebackFragment(c) {
			fragments = append(fragments, c)
		} else {
			normal = append(normal, *c)
		}
	}

	if len(fragments) < 3 && len(tracebackHeaders) == 0 {
		return clusters
	}

	allPy := append(tracebackHeaders, fragments...)
	sort.Slice(allPy, func(i, j int) bool {
		return allPy[i].LastSeen.Before(allPy[j].LastSeen)
	})

	var groups [][]*logsift.Cluster
	currentGroup := []*logsift.Cluster{allPy[0]}

	for i := 1; i < len(allPy); i++ {
		prevEnd := currentGroup[len(currentGroup)-1].LastSeen
		if allPy[i].FirstSeen.Sub(prevEnd) <= 5*time.Second {
			currentGroup = append(currentGroup, allPy[i])
		} else {
			groups = append(groups, currentGroup)
			currentGroup = []*logsift.Cluster{allPy[i]}
		}
	}
	groups = append(groups, currentGroup)

	for _, group := range groups {
		if len(group) < 3 {
			for _, c := range group {
				normal = append(normal, *c)
			}
			continue
		}

		merged := logsift.Cluster{
			Severity:  logsift.SeverityError,
			FirstSeen: group[0].FirstSeen,
			LastSeen:  group[0].LastSeen,
		}

		var bestHeader string
		var bestException string
		for _, c := range group {
			merged.Count += c.Count
			if c.FirstSeen.Before(merged.FirstSeen) {
				merged.FirstSeen = c.FirstSeen
			}
			if c.LastSeen.After(merged.LastSeen) {
				merged.LastSeen = c.LastSeen
			}
			if logsift.SeverityIndex(c.Severity) > logsift.SeverityIndex(merged.Severity) {
				merged.Severity = c.Severity
			}

			tpl := c.Template
			if len(c.Examples) > 0 {
				tpl = c.Examples[0]
			}
			if strings.Contains(tpl, "Traceback") && bestHeader == "" {
				bestHeader = tpl
			}
			if rePyExceptionClass.MatchString(tpl) && bestException == "" {
				bestException = tpl
			}
		}

		if bestHeader != "" {
			merged.Template = "Python exception: " + logsift.TruncateStr(bestHeader, 120)
		} else if bestException != "" {
			merged.Template = "Python exception: " + bestException
		} else {
			merged.Template = "Python traceback"
		}

		if bestHeader != "" {
			merged.Examples = []string{bestHeader}
		}
		if bestException != "" && bestException != bestHeader {
			merged.Examples = append(merged.Examples, bestException)
		}
		if len(merged.Examples) == 0 && len(group[0].Examples) > 0 {
			merged.Examples = []string{group[0].Examples[0]}
		}

		normal = append(normal, merged)
	}

	return normal
}

var (
	rePyFileFrame      = regexp.MustCompile(`(?m)^\s+File "`)
	rePyUnderline      = regexp.MustCompile(`(?m)^\s+[\^~]{5,}`)
	rePyRaiseAwait     = regexp.MustCompile(`(?m)^\s+(raise |await |return await |with \w)`)
	rePySelfCall       = regexp.MustCompile(`(?m)^\s+self\.\w+`)
	rePyAssignAwait    = regexp.MustCompile(`(?m)=\s+await\s+`)
	rePyExceptionClass = regexp.MustCompile(`(?m)^\w+(\.\w+)*\.\w*(Timeout|Error|Exception|Fault)\b`)
	rePyExceptionChain = regexp.MustCompile(`(?i)^(The above exception|During handling of the above)`)
)

func isPythonTracebackFragment(c *logsift.Cluster) bool {
	return matchesPyTracebackPattern(c.Template) ||
		slices.ContainsFunc(c.Examples, matchesPyTracebackPattern)
}

func matchesPyTracebackPattern(msg string) bool {
	return rePyUnderline.MatchString(msg) ||
		rePyRaiseAwait.MatchString(msg) ||
		rePySelfCall.MatchString(msg) ||
		rePyAssignAwait.MatchString(msg) ||
		rePyExceptionClass.MatchString(msg) ||
		rePyExceptionChain.MatchString(msg) ||
		rePyFileFrame.MatchString(msg)
}
