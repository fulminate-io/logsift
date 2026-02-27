package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/logging"
	"cloud.google.com/go/logging/logadmin"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/structpb"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("gcp", &gcpBackend{})
}

// gcpBackend implements logsift.Backend for GCP Cloud Logging.
type gcpBackend struct{}

// Available returns true when GCP credentials are configured.
// Supports both explicit service account JSON and ADC (Application Default Credentials)
// when a project ID is present without SA JSON (e.g., GKE workload identity).
func (b *gcpBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.GCPServiceAccountJSON != "" {
		return true
	}
	// ADC fallback: project ID without SA JSON (workload identity, gcloud auth, etc.)
	if creds.GCPProjectID != "" {
		return true
	}
	for _, p := range creds.GCPProjects {
		if p.ServiceAccountJSON != "" || p.ProjectID != "" {
			return true
		}
	}
	return false
}

// Search queries GCP Cloud Logging and returns normalized log entries.
// For multi-project setups, it queries all projects with credentials and merges results.
func (b *gcpBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	projects := b.resolveProjects(creds)
	if len(projects) == 0 {
		return nil, fmt.Errorf("gcp: no projects with credentials configured")
	}

	maxPerProject := q.MaxRawEntries
	if maxPerProject <= 0 {
		maxPerProject = 500
	}
	if len(projects) > 1 {
		maxPerProject = maxPerProject / len(projects)
		maxPerProject = max(maxPerProject, 50)
	}

	var allEntries []logsift.LogEntry
	var totalEstimate int

	for _, proj := range projects {
		entries, estimate, err := b.searchProject(ctx, proj, q, maxPerProject)
		if err != nil {
			// Log but continue — partial results from other projects are still useful.
			continue
		}
		allEntries = append(allEntries, entries...)
		totalEstimate += estimate

		if len(allEntries) >= q.MaxRawEntries {
			allEntries = allEntries[:q.MaxRawEntries]
			break
		}
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: totalEstimate,
	}, nil
}

// ListSources returns available log names for the configured GCP project(s).
func (b *gcpBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	projects := b.resolveProjects(creds)
	if len(projects) == 0 {
		return nil, fmt.Errorf("gcp: no projects with credentials configured")
	}

	var sources []logsift.SourceInfo
	seen := make(map[string]bool)

	for _, proj := range projects {
		client, err := b.newClient(ctx, proj)
		if err != nil {
			continue
		}

		it := client.Logs(ctx)
		for {
			logName, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}

			// logName is full path: "projects/<project>/logs/<logID>"
			shortName := extractLogID(logName)
			if prefix != "" && !strings.HasPrefix(strings.ToLower(shortName), strings.ToLower(prefix)) {
				continue
			}
			if seen[shortName] {
				continue
			}
			seen[shortName] = true

			desc := shortName
			if len(projects) > 1 {
				desc = fmt.Sprintf("%s (project: %s)", shortName, proj.projectID)
			}
			sources = append(sources, logsift.SourceInfo{
				Name:        shortName,
				Description: desc,
			})

			if len(sources) >= 100 {
				client.Close()
				return sources, nil
			}
		}
		client.Close()
	}

	return sources, nil
}

// gcpProject holds the credentials needed to query a single GCP project.
type gcpProject struct {
	projectID          string
	serviceAccountJSON string
}

// resolveProjects returns the list of GCP projects with valid credentials.
// Projects with a project ID but no SA JSON will use ADC (Application Default Credentials).
func (b *gcpBackend) resolveProjects(creds *logsift.Credentials) []gcpProject {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-project list.
	if len(creds.GCPProjects) > 0 {
		var projects []gcpProject
		for _, p := range creds.GCPProjects {
			if p.ProjectID == "" {
				continue
			}
			// Include projects with SA JSON or ADC-only (project ID without SA).
			projects = append(projects, gcpProject{
				projectID:          p.ProjectID,
				serviceAccountJSON: p.ServiceAccountJSON,
			})
		}
		if len(projects) > 0 {
			return projects
		}
	}

	// Fallback to flat/legacy fields. Supports both explicit SA JSON and ADC.
	if creds.GCPProjectID != "" {
		return []gcpProject{{
			projectID:          creds.GCPProjectID,
			serviceAccountJSON: creds.GCPServiceAccountJSON,
		}}
	}

	return nil
}

// newClient creates a logadmin client for a single project.
// When serviceAccountJSON is empty, the client uses Application Default Credentials
// (e.g., gcloud auth, GKE workload identity).
func (b *gcpBackend) newClient(ctx context.Context, proj gcpProject) (*logadmin.Client, error) {
	if proj.serviceAccountJSON == "" {
		// ADC fallback — SDK auto-discovers credentials from environment.
		return logadmin.NewClient(ctx, proj.projectID)
	}
	return logadmin.NewClient(ctx, proj.projectID,
		option.WithCredentialsJSON([]byte(proj.serviceAccountJSON)),
	)
}

// searchProject queries a single GCP project and returns normalized entries.
func (b *gcpBackend) searchProject(ctx context.Context, proj gcpProject, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, int, error) {
	client, err := b.newClient(ctx, proj)
	if err != nil {
		return nil, 0, fmt.Errorf("gcp: failed to create client for project %s: %w", proj.projectID, err)
	}
	defer client.Close()

	filter := buildGCPFilter(proj.projectID, q)

	opts := []logadmin.EntriesOption{
		logadmin.Filter(filter),
		logadmin.NewestFirst(),
		logadmin.PageSize(int32(maxEntries)),
	}

	it := client.Entries(ctx, opts...)

	var entries []logsift.LogEntry
	count := 0
	for {
		entry, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if count > 0 {
				// Return partial results.
				return entries, count, nil
			}
			return nil, 0, fmt.Errorf("gcp: error reading entries from project %s: %w", proj.projectID, err)
		}

		entries = append(entries, normalizeGCPEntry(entry))
		count++
		if count >= maxEntries {
			break
		}
	}

	return entries, count, nil
}

// buildGCPFilter constructs an Advanced Logs Filter string from a Query.
// Reference: https://cloud.google.com/logging/docs/view/logging-query-language
func buildGCPFilter(projectID string, q *logsift.Query) string {
	var parts []string

	// Time range — always included.
	if !q.StartTime.IsZero() {
		parts = append(parts, fmt.Sprintf(`timestamp >= "%s"`, q.StartTime.UTC().Format(time.RFC3339)))
	}
	if !q.EndTime.IsZero() {
		parts = append(parts, fmt.Sprintf(`timestamp <= "%s"`, q.EndTime.UTC().Format(time.RFC3339)))
	}

	// Severity filter.
	if q.SeverityMin != "" {
		gcpSev := mapSeverityToGCP(q.SeverityMin)
		if gcpSev != "" {
			parts = append(parts, fmt.Sprintf("severity >= %s", gcpSev))
		}
	}

	// Log source (log name).
	if q.Source != "" {
		// Accept both short ("stderr") and full ("projects/xxx/logs/stderr") forms.
		if strings.HasPrefix(q.Source, "projects/") {
			parts = append(parts, fmt.Sprintf(`logName="%s"`, q.Source))
		} else {
			parts = append(parts, fmt.Sprintf(`logName="projects/%s/logs/%s"`, projectID, q.Source))
		}
	}

	// Text filter — searches across textPayload, jsonPayload, and protoPayload.
	if q.TextFilter != "" {
		// Using the built-in text search which matches all payload types.
		parts = append(parts, escapeGCPTextFilter(q.TextFilter))
	}

	// Field filters — translate canonical names to GCP-native names.
	if len(q.FieldFilters) > 0 {
		mapped := logsift.MapFieldFilters(q.FieldFilters, logsift.FieldMappingGCP)
		for field, value := range mapped {
			parts = append(parts, fmt.Sprintf(`%s="%s"`, field, escapeGCPValue(value)))
		}
	}

	// Raw query — append as-is for advanced users.
	if q.RawQuery != "" {
		parts = append(parts, q.RawQuery)
	}

	return strings.Join(parts, "\n")
}

// mapSeverityToGCP maps our canonical severity to GCP severity names.
func mapSeverityToGCP(severity string) string {
	switch severity {
	case logsift.SeverityTrace, logsift.SeverityDebug:
		return "DEBUG"
	case logsift.SeverityInfo:
		return "INFO"
	case logsift.SeverityWarn:
		return "WARNING"
	case logsift.SeverityError:
		return "ERROR"
	case logsift.SeverityCritical:
		return "CRITICAL"
	default:
		return ""
	}
}

// mapGCPSeverity maps a GCP logging.Severity to our canonical severity.
func mapGCPSeverity(s logging.Severity) string {
	switch {
	case s >= logging.Emergency:
		return logsift.SeverityCritical
	case s >= logging.Alert:
		return logsift.SeverityCritical
	case s >= logging.Critical:
		return logsift.SeverityCritical
	case s >= logging.Error:
		return logsift.SeverityError
	case s >= logging.Warning:
		return logsift.SeverityWarn
	case s >= logging.Notice:
		return logsift.SeverityInfo
	case s >= logging.Info:
		return logsift.SeverityInfo
	case s >= logging.Debug:
		return logsift.SeverityDebug
	default:
		return logsift.SeverityInfo
	}
}

// normalizeGCPEntry converts a GCP log entry to our canonical LogEntry format.
func normalizeGCPEntry(entry *logging.Entry) logsift.LogEntry {
	le := logsift.LogEntry{
		Timestamp: entry.Timestamp,
		Severity:  mapGCPSeverity(entry.Severity),
		Message:   extractGCPMessage(entry),
	}

	// Reclassify severity based on embedded level indicators.
	// GKE marks all container stderr as ERROR; the actual level is often lower.
	// Only reclassify downward (never promote INFO→ERROR).
	if embedded := logsift.DetectEmbeddedSeverity(le.Message); embedded != "" {
		if !logsift.SeverityAtLeast(embedded, le.Severity) {
			le.Severity = embedded
		}
	}

	// Extract service and host from resource labels.
	if entry.Resource != nil && entry.Resource.Labels != nil {
		labels := entry.Resource.Labels
		// K8s container resource type.
		if v, ok := labels["container_name"]; ok {
			le.Service = v
		} else if v, ok := labels["service_name"]; ok {
			le.Service = v
		} else if v, ok := labels["module_id"]; ok {
			// App Engine.
			le.Service = v
		}
		if v, ok := labels["instance_id"]; ok {
			le.Host = v
		} else if v, ok := labels["pod_name"]; ok {
			le.Host = v
		}
	}

	// Override service from entry labels if present.
	if entry.Labels != nil {
		if v, ok := entry.Labels["k8s-pod/app"]; ok && le.Service == "" {
			le.Service = v
		}
	}

	return le
}

// extractGCPMessage extracts the text message from a GCP log entry payload.
// The SDK returns: string (textPayload), *structpb.Struct (jsonPayload),
// proto.Message (protoPayload), or nil.
func extractGCPMessage(entry *logging.Entry) string {
	switch p := entry.Payload.(type) {
	case string:
		return p
	case *structpb.Struct:
		// jsonPayload — the SDK returns the raw proto Struct, not map[string]any.
		return logsift.ExtractMessageFromMap(p.AsMap())
	case map[string]any:
		// Defensive: handle in case SDK behavior changes.
		return logsift.ExtractMessageFromMap(p)
	default:
		if entry.Payload == nil {
			return ""
		}
		// protoPayload or unknown type — try JSON marshaling.
		b, err := json.Marshal(entry.Payload)
		if err != nil {
			return fmt.Sprintf("%v", entry.Payload)
		}
		return string(b)
	}
}

// extractLogID extracts the log ID from a full GCP log name.
// "projects/my-project/logs/stderr" → "stderr"
// "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity" → "cloudaudit.googleapis.com/activity"
func extractLogID(fullName string) string {
	parts := strings.SplitN(fullName, "/logs/", 2)
	if len(parts) != 2 {
		return fullName
	}
	// URL-decode %2F back to /
	return strings.ReplaceAll(parts[1], "%2F", "/")
}

// escapeGCPTextFilter wraps the text filter for GCP's query language.
// Simple text is passed directly (GCP's global search). Quoted strings
// use exact match semantics.
func escapeGCPTextFilter(text string) string {
	// If already quoted, pass through.
	if strings.HasPrefix(text, `"`) && strings.HasSuffix(text, `"`) {
		return text
	}
	// Wrap in quotes for exact substring matching.
	return `"` + escapeGCPValue(text) + `"`
}

// escapeGCPValue escapes a value for use in GCP filter expressions.
func escapeGCPValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
