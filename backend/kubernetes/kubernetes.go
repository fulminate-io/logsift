package kubernetes

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	logsift "github.com/fulminate-io/logsift"
)

func init() {
	logsift.Register("kubernetes", &k8sBackend{})
}

// k8sBackend implements logsift.Backend for Kubernetes pod logs.
type k8sBackend struct{}

// k8sCluster holds the resolved credentials for a single Kubernetes cluster.
type k8sCluster struct {
	name              string
	kubeconfigContent string
	context           string
}

// Available returns true when kubeconfig credentials are configured.
func (b *k8sBackend) Available(creds *logsift.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.KubeconfigContent != "" {
		return true
	}
	for _, c := range creds.KubernetesClusters {
		if c.KubeconfigContent != "" {
			return true
		}
	}
	return false
}

// Search queries Kubernetes pod logs across all configured clusters.
func (b *k8sBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
	clusters := b.resolveClusters(creds)
	if len(clusters) == 0 {
		return nil, fmt.Errorf("kubernetes: no clusters with kubeconfig configured")
	}

	maxPerCluster := q.MaxRawEntries
	if maxPerCluster <= 0 {
		maxPerCluster = 500
	}
	if len(clusters) > 1 {
		maxPerCluster = maxPerCluster / len(clusters)
		maxPerCluster = max(maxPerCluster, 50)
	}

	var allEntries []logsift.LogEntry

	for _, cluster := range clusters {
		entries, err := b.searchCluster(ctx, cluster, q, maxPerCluster)
		if err != nil {
			// Log but continue — partial results from other clusters are still useful.
			continue
		}
		allEntries = append(allEntries, entries...)

		if len(allEntries) >= q.MaxRawEntries {
			allEntries = allEntries[:q.MaxRawEntries]
			break
		}
	}

	return &logsift.RawResults{
		Entries:       allEntries,
		TotalEstimate: len(allEntries),
	}, nil
}

// ListSources returns available namespaces from all configured clusters.
func (b *k8sBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
	clusters := b.resolveClusters(creds)
	if len(clusters) == 0 {
		return nil, fmt.Errorf("kubernetes: no clusters with kubeconfig configured")
	}

	var sources []logsift.SourceInfo
	seen := make(map[string]bool)

	for _, cluster := range clusters {
		clientset, err := b.newClientset(cluster)
		if err != nil {
			continue
		}

		nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ns := range nsList.Items {
			name := ns.Name
			if prefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true

			desc := name
			if len(clusters) > 1 {
				desc = fmt.Sprintf("%s (cluster: %s)", name, cluster.name)
			}
			sources = append(sources, logsift.SourceInfo{
				Name:        name,
				Description: desc,
			})

			if len(sources) >= 100 {
				return sources, nil
			}
		}
	}

	return sources, nil
}

// resolveClusters returns the list of Kubernetes clusters with valid kubeconfigs.
func (b *k8sBackend) resolveClusters(creds *logsift.Credentials) []k8sCluster {
	if creds == nil {
		return nil
	}

	// Prefer typed multi-cluster list.
	if len(creds.KubernetesClusters) > 0 {
		var clusters []k8sCluster
		for _, c := range creds.KubernetesClusters {
			if c.KubeconfigContent == "" {
				continue
			}
			clusters = append(clusters, k8sCluster{
				name:              c.Name,
				kubeconfigContent: c.KubeconfigContent,
				context:           c.Context,
			})
		}
		if len(clusters) > 0 {
			return clusters
		}
	}

	// Fallback to flat fields.
	if creds.KubeconfigContent != "" {
		return []k8sCluster{{
			name:              "default",
			kubeconfigContent: creds.KubeconfigContent,
			context:           creds.KubeContext,
		}}
	}

	return nil
}

// newClientset builds a kubernetes.Clientset from kubeconfig bytes.
func (b *k8sBackend) newClientset(cluster k8sCluster) (*kubernetes.Clientset, error) {
	config, err := clientcmd.NewClientConfigFromBytes([]byte(cluster.kubeconfigContent))
	if err != nil {
		return nil, fmt.Errorf("kubernetes: failed to parse kubeconfig for cluster %s: %w", cluster.name, err)
	}

	rawConfig, err := config.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("kubernetes: failed to get raw config for cluster %s: %w", cluster.name, err)
	}

	if cluster.context != "" {
		rawConfig.CurrentContext = cluster.context
	}

	restConfig, err := clientcmd.NewDefaultClientConfig(rawConfig, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubernetes: failed to build rest config for cluster %s: %w", cluster.name, err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: failed to create clientset for cluster %s: %w", cluster.name, err)
	}

	return clientset, nil
}

// searchCluster queries pod logs from a single Kubernetes cluster.
func (b *k8sBackend) searchCluster(ctx context.Context, cluster k8sCluster, q *logsift.Query, maxEntries int) ([]logsift.LogEntry, error) {
	clientset, err := b.newClientset(cluster)
	if err != nil {
		return nil, err
	}

	// Resolve namespace from query.
	namespace := resolveNamespace(q)

	// Build label selector.
	labelSelector := buildLabelSelector(q)

	// List pods matching selector.
	listOpts := metav1.ListOptions{}
	if labelSelector != "" {
		listOpts.LabelSelector = labelSelector
	}

	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: failed to list pods in cluster %s: %w", cluster.name, err)
	}

	// Filter by pod name prefix if specified.
	podFilter := q.FieldFilters["pod"]
	containerFilter := q.FieldFilters["container"]

	// Build (pod, container) pairs for log fetching.
	type podContainer struct {
		podName       string
		containerName string
	}
	var targets []podContainer

	for i := range pods.Items {
		pod := &pods.Items[i]
		if podFilter != "" && !strings.HasPrefix(pod.Name, podFilter) {
			continue
		}

		// Collect init containers and regular containers.
		allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...)
		for _, c := range allContainers {
			if containerFilter != "" && c.Name != containerFilter {
				continue
			}
			targets = append(targets, podContainer{
				podName:       pod.Name,
				containerName: c.Name,
			})
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	// Fetch logs concurrently with a semaphore.
	const maxConcurrent = 10
	sem := make(chan struct{}, maxConcurrent)
	var mu sync.Mutex
	var allEntries []logsift.LogEntry
	var wg sync.WaitGroup

	// Build pod log options.
	logOpts := &corev1.PodLogOptions{
		Timestamps: true,
	}
	if !q.StartTime.IsZero() {
		sinceTime := metav1.NewTime(q.StartTime)
		logOpts.SinceTime = &sinceTime
	}

	// Cap tail lines to avoid pulling excessive data per container.
	tailLines := int64(maxEntries)
	logOpts.TailLines = &tailLines

	for _, target := range targets {
		wg.Add(1)
		go func(pc podContainer) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			opts := logOpts.DeepCopy()
			opts.Container = pc.containerName

			stream, err := clientset.CoreV1().Pods(namespace).GetLogs(pc.podName, opts).Stream(ctx)
			if err != nil {
				return
			}
			defer stream.Close()

			entries := scanLogStream(stream, pc.podName, pc.containerName, q)

			mu.Lock()
			allEntries = append(allEntries, entries...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	// Sort by timestamp desc, cap at maxEntries.
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.After(allEntries[j].Timestamp)
	})
	if len(allEntries) > maxEntries {
		allEntries = allEntries[:maxEntries]
	}

	return allEntries, nil
}

// resolveNamespace determines the namespace from query fields.
func resolveNamespace(q *logsift.Query) string {
	// Source field is treated as namespace for kubernetes.
	if q.Source != "" {
		return q.Source
	}
	if ns, ok := q.FieldFilters["namespace"]; ok {
		return ns
	}
	// Empty string = all namespaces.
	return ""
}

// buildLabelSelector constructs a Kubernetes label selector from query fields.
func buildLabelSelector(q *logsift.Query) string {
	// Raw query is passed through as a label selector.
	if q.RawQuery != "" {
		return q.RawQuery
	}

	// Map service filter to standard app label.
	if service, ok := q.FieldFilters["service"]; ok && service != "" {
		// Try app.kubernetes.io/name first (standard), fallback to app (common).
		return fmt.Sprintf("app.kubernetes.io/name=%s", service)
	}

	return ""
}

// scanLogStream reads a pod log stream and parses entries with client-side filtering.
func scanLogStream(reader io.Reader, podName, containerName string, q *logsift.Query) []logsift.LogEntry {
	scanner := bufio.NewScanner(reader)
	// Allow up to 1MB per line for large JSON logs.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var entries []logsift.LogEntry
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := parseLine(line, podName, containerName)

		// Client-side text filter.
		if q.TextFilter != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(q.TextFilter)) {
			continue
		}

		// Client-side severity filter.
		if q.SeverityMin != "" && !logsift.SeverityAtLeast(entry.Severity, q.SeverityMin) {
			continue
		}

		entries = append(entries, entry)
	}

	return entries
}

// parseLine parses a single Kubernetes log line into a LogEntry.
// K8s log lines with timestamps enabled have the format: "RFC3339Nano <message>"
func parseLine(line, podName, containerName string) logsift.LogEntry {
	entry := logsift.LogEntry{
		Timestamp: time.Now(),
		Severity:  logsift.SeverityInfo,
		Service:   containerName,
		Host:      podName,
	}

	// Parse K8s timestamp prefix (RFC3339Nano).
	if idx := strings.IndexByte(line, ' '); idx > 0 && idx < 40 {
		if ts, err := time.Parse(time.RFC3339Nano, line[:idx]); err == nil {
			entry.Timestamp = ts
			line = line[idx+1:]
		}
	}

	entry.Message = line

	// Try JSON parsing for structured logs.
	if len(line) > 0 && line[0] == '{' {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			// Extract message.
			if msg := logsift.ExtractMessageFromMap(m); msg != line {
				entry.Message = msg
			}
			// Extract severity from JSON fields.
			for _, key := range []string{"level", "severity", "lvl"} {
				if v, ok := m[key]; ok {
					if s, ok := v.(string); ok && s != "" {
						entry.Severity = logsift.ParseSeverity(s)
						return entry
					}
				}
			}
		}
	}

	// Fall back to embedded severity detection for plain text.
	if embedded := logsift.DetectEmbeddedSeverity(entry.Message); embedded != "" {
		entry.Severity = embedded
	}

	return entry
}
