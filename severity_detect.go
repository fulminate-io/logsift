package logsift

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// reEmbeddedLevel matches common embedded severity indicators in log messages.
// GKE marks all stderr output as ERROR severity regardless of actual log level,
// so we detect the real level from message content and reclassify downward.
var reEmbeddedLevel = regexp.MustCompile(
	`(?i)` +
		`(?:` +
		`"?level"?\s*[:=]\s*"?(\w+)"?` + // level=info, "level":"info", level: warn
		`|` +
		`\t(trace|debug|info|warn(?:ing)?|error|fatal|panic)\t` + // \tinfo\t (zerolog tab-delimited)
		`|` +
		`\[(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|PANIC)\]` + // [INFO] (bracket style)
		`|` +
		`^(TRACE|DEBUG|INFO|WARNI?(?:NG)?|ERROR|FATAL|PANIC|CRITICAL)\s` + // ERROR [asyncio] (severity at start of line)
		`)`,
)

// DetectEmbeddedSeverity checks the beginning of a log message for an embedded
// severity indicator. Returns the parsed canonical severity or "" if none found.
func DetectEmbeddedSeverity(msg string) string {
	// Only check first 200 chars for performance.
	check := msg
	if len(check) > 200 {
		check = check[:200]
	}
	m := reEmbeddedLevel.FindStringSubmatch(check)
	if m == nil {
		return ""
	}
	// One of the capture groups will be non-empty.
	for _, g := range m[1:] {
		if g != "" {
			return ParseSeverity(g)
		}
	}
	return ""
}

// ExtractMessageFromMap extracts a message string from a JSON payload map.
// Tries common field names in priority order.
func ExtractMessageFromMap(m map[string]any) string {
	// Try common message fields first.
	for _, key := range []string{"message", "msg", "event", "textPayload", "log", "body"} {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
			// If the field is a nested object, recurse into it.
			if nested, ok := v.(map[string]any); ok {
				if s := ExtractMessageFromMap(nested); s != "" {
					return s
				}
			}
		}
	}

	// Fall back to JSON representation.
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprintf("%v", m)
	}
	return string(b)
}
