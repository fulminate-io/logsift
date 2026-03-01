package cloudwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("cloudwatch", &cwBackend{})
}

// cwBackend implements logsift.Backend for AWS CloudWatch Logs.
type cwBackend struct{}

// cwInstance holds the resolved credentials for a single CloudWatch instance.
type cwInstance struct {
	name            string
	region          string
	profile         string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	logGroupPrefix  string // optional default log group prefix
}

// Available returns true when at least one CloudWatch instance is configured.
// Also detects standard AWS SDK env vars (AWS_REGION, AWS_DEFAULT_REGION)
// so users don't need logsift-specific config when AWS credentials are already set.
func (b *cwBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	// Flat fields.
	if creds.CloudWatchRegion != "" {
		return true
	}
	// Multi-instance list.
	for _, inst := range creds.CloudWatchInstances {
		if inst.Region != "" {
			return true
		}
	}
	// Detect standard AWS env vars — the SDK will use them automatically.
	if os.Getenv("AWS_REGION") != "" || os.Getenv("AWS_DEFAULT_REGION") != "" {
		return true
	}
	return false
}

// Search queries CloudWatch Logs from all configured instances.
func (b *cwBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("cloudwatch: no instances configured")
	}

	maxPerInstance := q.MaxRawEntries
	if maxPerInstance <= 0 {
		maxPerInstance = 500
	}
	if len(instances) > 1 {
		maxPerInstance = maxPerInstance / len(instances)
		maxPerInstance = max(maxPerInstance, 50)
	}
	// CloudWatch FilterLogEvents limit is 10,000.
	if maxPerInstance > 10000 {
		maxPerInstance = 10000
	}

	var allEntries []logsift.LogEntry
	var errs []string

	for _, inst := range instances {
		entries, err := b.searchInstance(ctx, inst, q, maxPerInstance)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", inst.name, err))
			continue
		}
		allEntries = append(allEntries, entries...)

		if len(allEntries) >= q.MaxRawEntries {
			allEntries = allEntries[:q.MaxRawEntries]
			break
		}
	}

	// If all instances failed, return the errors instead of empty results.
	if len(allEntries) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("cloudwatch: all instances failed: %s", strings.Join(errs, "; "))
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available log groups from CloudWatch.
func (b *cwBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	instances := b.resolveInstances(creds)
	if len(instances) == 0 {
		return nil, fmt.Errorf("cloudwatch: no instances configured")
	}

	var sources []logsift.SourceInfo
	var errs []string
	seen := make(map[string]bool)

	for _, inst := range instances {
		client, err := b.newClient(ctx, inst)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", inst.name, err))
			continue
		}

		input := &cloudwatchlogs.DescribeLogGroupsInput{
			Limit: aws.Int32(50),
		}
		if prefix != "" {
			input.LogGroupNamePrefix = aws.String(prefix)
		}

		// Paginate through log groups.
		var describeErr error
		for {
			output, err := client.DescribeLogGroups(ctx, input)
			if err != nil {
				describeErr = err
				break
			}

			for _, lg := range output.LogGroups {
				name := aws.ToString(lg.LogGroupName)
				if seen[name] {
					continue
				}
				seen[name] = true

				desc := name
				if len(instances) > 1 {
					desc = fmt.Sprintf("%s (instance: %s)", name, inst.name)
				}
				sources = append(sources, logsift.SourceInfo{
					Name:        name,
					Description: desc,
				})

				if len(sources) >= 100 {
					return sources, nil
				}
			}

			if output.NextToken == nil {
				break
			}
			input.NextToken = output.NextToken
		}
		if describeErr != nil && len(sources) == 0 {
			errs = append(errs, fmt.Sprintf("%s: %v", inst.name, describeErr))
		}
	}

	if len(sources) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("cloudwatch: all instances failed: %s", strings.Join(errs, "; "))
	}

	return sources, nil
}

// resolveInstances builds the list of CloudWatch instances from credentials.
func (b *cwBackend) resolveInstances(creds *logsift.Credentials) []cwInstance {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-instance list.
	if len(creds.CloudWatchInstances) > 0 {
		var instances []cwInstance
		for _, c := range creds.CloudWatchInstances {
			if c.Region == "" {
				continue
			}
			instances = append(instances, cwInstance{
				name:            c.Name,
				region:          c.Region,
				profile:         c.Profile,
				accessKeyID:     c.AccessKeyID,
				secretAccessKey: c.SecretAccessKey,
				sessionToken:    c.SessionToken,
				logGroupPrefix:  c.LogGroupPrefix,
			})
		}
		if len(instances) > 0 {
			return instances
		}
	}

	// Fallback to flat fields.
	if creds.CloudWatchRegion != "" {
		return []cwInstance{{
			name:           "default",
			region:         creds.CloudWatchRegion,
			profile:        creds.CloudWatchProfile,
			logGroupPrefix: creds.CloudWatchLogGroupPrefix,
		}}
	}

	// Detect standard AWS env vars — let the SDK resolve region and credentials.
	if region := os.Getenv("AWS_REGION"); region != "" {
		return []cwInstance{{
			name:           "default",
			region:         region,
			logGroupPrefix: creds.CloudWatchLogGroupPrefix,
		}}
	}
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		return []cwInstance{{
			name:           "default",
			region:         region,
			logGroupPrefix: creds.CloudWatchLogGroupPrefix,
		}}
	}

	return nil
}

// newClient creates a CloudWatch Logs client for a single instance.
func (b *cwBackend) newClient(ctx context.Context, inst cwInstance) (*cloudwatchlogs.Client, error) {
	var opts []func(*config.LoadOptions) error

	opts = append(opts, config.WithRegion(inst.region))

	if inst.profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(inst.profile))
	}

	if inst.accessKeyID != "" && inst.secretAccessKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(inst.accessKeyID, inst.secretAccessKey, inst.sessionToken),
		))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudwatch: failed to load AWS config for %s: %w", inst.name, err)
	}

	return cloudwatchlogs.NewFromConfig(cfg), nil
}

// searchInstance queries a single CloudWatch instance and returns normalized log entries.
func (b *cwBackend) searchInstance(ctx context.Context, inst cwInstance, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	client, err := b.newClient(ctx, inst)
	if err != nil {
		return nil, err
	}

	logGroupName := resolveLogGroup(q, inst)
	if logGroupName == "" {
		return nil, fmt.Errorf("cloudwatch: no log group specified (use 'source' parameter or set LOGSIFT_CW_LOG_GROUP_PREFIX env var)")
	}

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroupName),
		Limit:        aws.Int32(int32(min(maxEntries, 10000))),
	}

	if !q.StartTime.IsZero() {
		input.StartTime = aws.Int64(q.StartTime.UnixMilli())
	}
	if !q.EndTime.IsZero() {
		input.EndTime = aws.Int64(q.EndTime.UnixMilli())
	}

	// Build filter pattern from text filter and field filters.
	filterPattern := buildFilterPattern(q)
	if filterPattern != "" {
		input.FilterPattern = aws.String(filterPattern)
	}

	// If raw query is provided, use it as the filter pattern (overrides).
	if q.RawQuery != "" {
		input.FilterPattern = aws.String(q.RawQuery)
	}

	var entries []logsift.LogEntry

	// Paginate through results.
	for {
		output, err := client.FilterLogEvents(ctx, input)
		if err != nil {
			if len(entries) > 0 {
				// Return partial results.
				break
			}
			return nil, fmt.Errorf("cloudwatch: FilterLogEvents for %s: %w", inst.name, err)
		}

		for _, event := range output.Events {
			entry := normalizeEntry(event, logGroupName)

			// Client-side text filter (backup for patterns CloudWatch can't handle).
			if q.TextFilter != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(q.TextFilter)) {
				continue
			}

			// Client-side severity filter.
			if q.SeverityMin != "" && !logsift.SeverityAtLeast(entry.Severity, q.SeverityMin) {
				continue
			}

			entries = append(entries, entry)
		}

		if len(entries) >= maxEntries {
			entries = entries[:maxEntries]
			break
		}

		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	// Sort by timestamp desc.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, nil
}

// resolveLogGroup determines the CloudWatch log group name from the query.
func resolveLogGroup(q *logsift.Query, inst cwInstance) string {
	if q.Source != "" {
		// If source already looks like a log group path, use as-is.
		if strings.HasPrefix(q.Source, "/") || strings.Contains(q.Source, "/") {
			return q.Source
		}
		// If a prefix is configured, combine them.
		if inst.logGroupPrefix != "" {
			return inst.logGroupPrefix + q.Source
		}
		// Otherwise use the source as-is (could be a log group name).
		return q.Source
	}
	return ""
}

// buildFilterPattern constructs a CloudWatch filter pattern from query fields.
// CloudWatch filter patterns use a simple syntax:
//   - Simple text: "ERROR" matches log events containing "ERROR"
//   - Quoted terms: "connection timeout" for exact phrase
//   - JSON patterns: { $.level = "error" }
func buildFilterPattern(q *logsift.Query) string {
	// CloudWatch doesn't have structured field selectors in the same way
	// as other providers. Field filters become JSON property matchers.
	// For simplicity, we use the text filter directly.
	if q.TextFilter != "" {
		// Wrap in quotes for exact substring matching.
		return fmt.Sprintf("%q", q.TextFilter)
	}
	return ""
}

// normalizeEntry converts a CloudWatch FilteredLogEvent into a LogEntry.
func normalizeEntry(event cwTypes.FilteredLogEvent, logGroupName string) logsift.LogEntry {
	entry := logsift.LogEntry{
		Timestamp: time.Now(),
		Severity:  logsift.SeverityInfo,
		Service:   extractServiceFromLogGroup(logGroupName),
	}

	// Parse timestamp from milliseconds.
	if event.Timestamp != nil {
		entry.Timestamp = time.UnixMilli(*event.Timestamp)
	}

	// Host from log stream name.
	if event.LogStreamName != nil {
		entry.Host = *event.LogStreamName
		// Truncate long ECS/Fargate stream names for readability.
		if len(entry.Host) > 60 {
			entry.Host = entry.Host[:57] + "..."
		}
	}

	// Parse the log message for content and severity.
	msg := aws.ToString(event.Message)
	entry.Message, entry.Severity = parseLogMessage(msg)

	return entry
}

// extractServiceFromLogGroup extracts a service name from a CloudWatch log group name.
// Common patterns:
//
//	/ecs/<cluster>/<service> → service
//	/aws/lambda/<function>  → function
//	/aws/ecs/<service>      → service
//	<anything>              → last path segment
func extractServiceFromLogGroup(logGroup string) string {
	parts := strings.Split(strings.TrimPrefix(logGroup, "/"), "/")
	if len(parts) == 0 {
		return logGroup
	}
	// Return the last meaningful segment.
	return parts[len(parts)-1]
}

// parseLogMessage extracts message content and severity from a raw CloudWatch log line.
// CloudWatch log formats vary widely:
//   - Pure JSON: {"level":"error","msg":"..."}
//   - Logger-prefixed JSON: [src.app.services_v2.foo] {"event":"...","level":"warning"}
//   - Severity-prefixed: ERROR some message text
//   - Plain text: various application output
func parseLogMessage(line string) (message, severity string) {
	message = strings.TrimSpace(line)
	severity = logsift.SeverityInfo

	if message == "" {
		return
	}

	// Strip logger prefix: [some.logger.name] {json...}
	// Common in Python structlog output via CloudWatch.
	jsonBody := message
	if message[0] == '[' {
		if end := strings.Index(message, "] "); end >= 0 {
			rest := strings.TrimSpace(message[end+2:])
			if len(rest) > 0 && rest[0] == '{' {
				jsonBody = rest
			}
		}
	}

	// Try JSON parsing for structured logs.
	if len(jsonBody) > 0 && jsonBody[0] == '{' {
		if msg, sev, ok := parseJSONLog(jsonBody); ok {
			message = msg
			severity = sev
			return
		}
	}

	// Some CloudWatch log lines have a severity prefix (e.g., "ERROR ..." or "[ERROR] ...").
	if idx := strings.IndexByte(message, ' '); idx > 0 && idx <= 8 {
		prefix := strings.Trim(message[:idx], "[]")
		if sev := logsift.ParseSeverity(prefix); sev != logsift.SeverityInfo || strings.EqualFold(prefix, "INFO") {
			rest := strings.TrimSpace(message[idx+1:])
			if len(rest) > 0 {
				severity = sev
				// Strip logger prefix after severity: INFO [logger.name] {json...}
				if rest[0] == '[' {
					if end := strings.Index(rest, "] "); end >= 0 {
						afterLogger := strings.TrimSpace(rest[end+2:])
						if len(afterLogger) > 0 && afterLogger[0] == '{' {
							rest = afterLogger
						}
					}
				}
				message = rest
				// If the rest is JSON, parse it.
				if len(rest) > 0 && rest[0] == '{' {
					if msg, sevJSON, ok := parseJSONLog(rest); ok {
						message = msg
						if sevJSON != logsift.SeverityInfo {
							severity = sevJSON
						}
						return
					}
				}
				return
			}
		}
	}

	// Fall back to embedded severity detection for plain text.
	if embedded := logsift.DetectEmbeddedSeverity(message); embedded != "" {
		severity = embedded
	}

	return
}

// parseJSONLog parses a JSON log line and extracts message and severity.
// Returns (message, severity, ok).
func parseJSONLog(line string) (string, string, bool) {
	return parseJSONLogDepth(line, 0)
}

func parseJSONLogDepth(line string, depth int) (string, string, bool) {
	if depth > 3 {
		return line, logsift.SeverityInfo, false
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return "", "", false
	}

	msg := logsift.ExtractMessageFromMap(m)
	sev := extractSeverityFromMap(m)

	// Unwrap container log wrappers: the extracted message may itself be JSON
	// (e.g., {"time":"...","stream":"stderr","log":"{\"event\":\"...\"}"}).
	msg, sev = unwrapNestedMessage(msg, sev, depth+1)

	return msg, sev, true
}

// unwrapNestedMessage handles container log wrappers where the extracted
// message is itself JSON or has a "SEVERITY [logger] {json}" prefix.
func unwrapNestedMessage(msg, sev string, depth int) (string, string) {
	if len(msg) == 0 {
		return msg, sev
	}

	// Direct JSON: recurse into it.
	if msg[0] == '{' {
		if innerMsg, innerSev, ok := parseJSONLogDepth(msg, depth); ok {
			if innerSev != logsift.SeverityInfo {
				sev = innerSev
			}
			return innerMsg, sev
		}
		return msg, sev
	}

	// "SEVERITY [logger] {json}" or "SEVERITY {json}" pattern.
	// E.g., "INFO  [platform_api] {\"event\":\"Starting request\",...}"
	rest := msg
	if idx := strings.IndexByte(rest, ' '); idx > 0 && idx <= 8 {
		prefix := strings.Trim(rest[:idx], "[]")
		if prefixSev := logsift.ParseSeverity(prefix); prefixSev != logsift.SeverityInfo || strings.EqualFold(prefix, "INFO") {
			if prefixSev != logsift.SeverityInfo {
				sev = prefixSev
			}
			rest = strings.TrimSpace(rest[idx+1:])
		}
	}

	// Strip logger prefix: [logger.name] {json}
	if len(rest) > 0 && rest[0] == '[' {
		if end := strings.Index(rest, "] "); end >= 0 {
			afterLogger := strings.TrimSpace(rest[end+2:])
			if len(afterLogger) > 0 && afterLogger[0] == '{' {
				rest = afterLogger
			}
		}
	}

	// Parse remaining JSON.
	if len(rest) > 0 && rest[0] == '{' {
		if innerMsg, innerSev, ok := parseJSONLogDepth(rest, depth); ok {
			if innerSev != logsift.SeverityInfo {
				sev = innerSev
			}
			return innerMsg, sev
		}
	}

	return msg, sev
}

// extractSeverityFromMap finds severity in a JSON map, searching nested message objects too.
func extractSeverityFromMap(m map[string]any) string {
	sevKeys := []string{"level", "severity", "lvl", "log_level"}
	for _, key := range sevKeys {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return logsift.ParseSeverity(s)
			}
		}
	}
	// Check nested message/log objects for severity.
	for _, key := range []string{"message", "msg", "log"} {
		if v, ok := m[key]; ok {
			if nested, ok := v.(map[string]any); ok {
				if sev := extractSeverityFromMap(nested); sev != logsift.SeverityInfo {
					return sev
				}
			}
		}
	}
	return logsift.SeverityInfo
}
