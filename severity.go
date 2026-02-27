package logsift

import "strings"

// Severity levels ordered from least to most severe.
const (
	SeverityTrace    = "TRACE"
	SeverityDebug    = "DEBUG"
	SeverityInfo     = "INFO"
	SeverityWarn     = "WARN"
	SeverityError    = "ERROR"
	SeverityCritical = "CRITICAL"
)

// severityOrder maps severity strings to numeric order for comparison.
var severityOrder = map[string]int{
	SeverityTrace:    0,
	SeverityDebug:    1,
	SeverityInfo:     2,
	SeverityWarn:     3,
	SeverityError:    4,
	SeverityCritical: 5,
}

// ParseSeverity normalizes a severity string to canonical form.
// Returns SeverityInfo for unrecognized values.
func ParseSeverity(s string) string {
	upper := strings.ToUpper(strings.TrimSpace(s))
	switch upper {
	case SeverityTrace:
		return SeverityTrace
	case SeverityDebug, "DBG":
		return SeverityDebug
	case SeverityInfo, "INFORMATION", "NOTICE":
		return SeverityInfo
	case SeverityWarn, "WARNING":
		return SeverityWarn
	case SeverityError, "ERR", "SEVERE", "FATAL":
		return SeverityError
	case SeverityCritical, "CRIT", "ALERT", "EMERGENCY", "EMERG", "PANIC":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// SeverityAtLeast returns true if severity is at or above minSeverity.
func SeverityAtLeast(severity, minSeverity string) bool {
	return severityOrder[severity] >= severityOrder[minSeverity]
}

// SeverityIndex returns the numeric index of a severity level.
// Useful for cross-package severity comparisons.
func SeverityIndex(severity string) int {
	return severityOrder[severity]
}

// SeveritySymbol returns a display symbol for the severity level.
func SeveritySymbol(severity string) string {
	switch severity {
	case SeverityCritical, SeverityError:
		return "!!"
	case SeverityWarn:
		return "!"
	default:
		return " "
	}
}
