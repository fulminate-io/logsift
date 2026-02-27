package reducer

import (
	"regexp"

	"github.com/fulminate-io/logsift"
)

func init() {
	logsift.RegisterConsolidator(&keywordUpliftConsolidator{})
}

type keywordUpliftConsolidator struct{}

func (k *keywordUpliftConsolidator) Name() string  { return "keyword_uplift" }
func (k *keywordUpliftConsolidator) Priority() int { return 30 }

// reBuiltinNegativeKeywords matches universal failure/problem indicators.
// These words indicate problems regardless of domain — web servers, databases,
// IoT devices, Kubernetes, CI/CD, etc.
var reBuiltinNegativeKeywords = regexp.MustCompile(
	`(?i)\b(` +
		`fail(?:ed|ure|ing)?` +
		`|error(?:ed|s)?` +
		`|timeout` +
		`|timed\s+out` +
		`|refused` +
		`|denied` +
		`|panic(?:ked)?` +
		`|crash(?:ed)?` +
		`|fatal` +
		`|exception` +
		`|rejected` +
		`|unavailable` +
		`|exceeded` +
		`|overflow` +
		`|corrupt(?:ed|ion)?` +
		`|abort(?:ed)?` +
		`|broken` +
		`|violation` +
		`)\b`)

func (k *keywordUpliftConsolidator) Consolidate(clusters []logsift.Cluster) []logsift.Cluster {
	for i := range clusters {
		if clusters[i].Severity != logsift.SeverityInfo {
			continue
		}
		if reBuiltinNegativeKeywords.MatchString(clusters[i].Template) {
			clusters[i].Severity = logsift.SeverityWarn
			continue
		}
		// Also check examples — sometimes the template is wildcarded
		// but the example contains the keyword.
		for _, ex := range clusters[i].Examples {
			if reBuiltinNegativeKeywords.MatchString(ex) {
				clusters[i].Severity = logsift.SeverityWarn
				break
			}
		}
	}
	return clusters
}
