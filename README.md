# logsift

An MCP server that searches logs across cloud providers and returns clustered, reduced output designed for LLM consumption. Instead of dumping thousands of raw lines, logsift extracts patterns, ranks by signal, and fits results within a token budget.

```
Raw Logs (5,000 entries)
  → Drain Clustering (pattern extraction)
    → Consolidators (Go panics, Python tracebacks, structural noise)
      → Signal Ranking (severity → frequency → recency)
        → Token Budget (fits LLM context)
          → 30-70 clusters in ~3,000 tokens (95-99% reduction)
```

Works with any MCP-compatible client — Claude Code, Cursor, Windsurf, or your own.

## Supported Backends

| Backend | Status | Source Parameter |
|---------|--------|-----------------|
| AWS CloudWatch Logs | Stable | Log group path |
| GCP Cloud Logging | Stable | Log name |
| Grafana Loki | Stable | Namespace |
| Kubernetes Pod Logs | Stable | Namespace |
| Datadog | [Help wanted](#adding-a-new-backend) | — |
| Splunk | [Help wanted](#adding-a-new-backend) | — |
| Elastic / OpenSearch | [Help wanted](#adding-a-new-backend) | — |
| Azure Monitor | [Help wanted](#adding-a-new-backend) | — |
| Sumo Logic | [Help wanted](#adding-a-new-backend) | — |

## Supported Stack Consolidators

The reduction pipeline includes consolidators that recognize language-specific crash output and merge fragmented lines into a single cluster.

| Language | Status | What It Consolidates |
|----------|--------|---------------------|
| Go | Stable | Goroutine dumps, register dumps, panic traces |
| Python | Stable | Tracebacks with `File "..."` frames, exception chains |
| Java | [Help wanted](#adding-a-new-consolidator) | `at com.foo.Bar` stack traces, `Caused by:` chains |
| Node.js | [Help wanted](#adding-a-new-consolidator) | Async stack traces, unhandled rejections |
| Rust | [Help wanted](#adding-a-new-consolidator) | Panic backtraces |
| .NET | [Help wanted](#adding-a-new-consolidator) | Exception stack traces |
| Ruby | [Help wanted](#adding-a-new-consolidator) | Backtraces with gem paths |

## Quick Start

```bash
go install github.com/fulminate-io/logsift/cmd/logsift@latest
```

Or build from source:

```bash
git clone https://github.com/fulminate-io/logsift.git
cd logsift
make build    # binary at build/logsift
make setup    # auto-registers in ~/.claude.json
```

### Configure

Add to your MCP client config (e.g., `~/.claude.json` for Claude Code):

```json
{
  "mcpServers": {
    "logsift": {
      "command": "logsift",
      "env": {
        "LOGSIFT_LOKI_ADDRESS": "http://localhost:3100",
        "LOGSIFT_CW_REGION": "us-east-1",
        "LOGSIFT_GCP_PROJECTS": "my-project",
        "KUBECONFIG": "~/.kube/config"
      }
    }
  }
}
```

Only set env vars for the backends you use. See [Configuration](#configuration) for the full list.

## Example Output

Ask your AI assistant "what errors are happening in prod?" and logsift returns:

```
[search_logs] 2,181 entries -> 9 clusters (1h window, cloudwatch)

!! CRITICAL [x800, 17:29-17:32] Critical attempts processing workflow task

!! ERROR [x1281, 17:29-17:32] Failed handling activation on workflow with run ID <*>
  -> Failed handling activation on workflow with run ID 019c9b5f-26ce-7c50-b9a5-f068bdf3e013
  -> Failed handling activation on workflow with run ID 019c9b27-6c3f-76f3-8e02-6a2552498721

!! ERROR [x9, 17:29-17:31] Worker startup attempt 1/3 failed: <*>

  INFO [x50, 17:30-17:32] processing http request

[656/4000 tokens]
```

- `!!` = ERROR/CRITICAL, `!` = WARN, blank = INFO/DEBUG
- `[x25, 12:03-12:15]` = 25 occurrences across that time range
- `<*>` = variable parts (IDs, timestamps, etc.) replaced by the Drain algorithm
- `->` lines show concrete examples when the template has wildcards
- Footer shows tokens used vs. budget; a `[cursor: ...]` appears when there's more

## How It Works

```
┌─────────────┐     ┌──────────────────────┐     ┌──────────────┐
│  MCP Client │────▶│      logsift         │────▶│   Backends   │
│  (Claude,   │◀────│    stdio JSON-RPC    │◀────│  GCP | K8s   │
│   Cursor)   │     │                      │     │  Loki | CW   │
└─────────────┘     └──────────┬───────────┘     └──────────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Reduction Pipeline  │
                    │                      │
                    │  1. Severity filter   │
                    │  2. Exact dedup       │
                    │  3. Drain clustering  │
                    │  4. Consolidators     │  ← Go panics, Python TBs, ...
                    │  5. Stack grouping    │
                    │  6. Signal-first sort │
                    │  7. Token truncation  │
                    └──────────────────────┘
```

**Backends** translate queries into provider-native syntax (LogQL, GCP Advanced Logs Filter, CloudWatch Filter Patterns, kubectl) and return normalized `LogEntry` structs.

**The Drain algorithm** (step 3) groups log messages into template patterns. It tokenizes messages, replaces variable parts (UUIDs, IPs, timestamps) with `<*>` wildcards, and merges similar patterns using a prefix-tree with similarity matching.

**Consolidators** (step 4) are plugins that recognize domain-specific patterns. The Go consolidator merges 50 goroutine dump fragments into a single "Go runtime crash" cluster at CRITICAL severity. The Python consolidator does the same for tracebacks. Adding a consolidator for your language is one of the easiest ways to contribute — see [Adding a New Consolidator](#adding-a-new-consolidator).

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| **GCP Cloud Logging** | |
| `LOGSIFT_GCP_PROJECTS` | Comma-separated GCP project IDs (uses ADC) |
| `LOGSIFT_GCP_SERVICE_ACCOUNT_JSON` | Path to service account key file |
| **Kubernetes** | |
| `KUBECONFIG` | Path to kubeconfig (default: `~/.kube/config`) |
| `LOGSIFT_KUBE_CONTEXT` | Kubernetes context to use (default: current) |
| **Grafana Loki** | |
| `LOGSIFT_LOKI_ADDRESS` | Loki base URL (e.g., `http://localhost:3100`) |
| `LOGSIFT_LOKI_TENANT_ID` | X-Scope-OrgID for multi-tenant Loki |
| `LOGSIFT_LOKI_USERNAME` | Basic auth username |
| `LOGSIFT_LOKI_PASSWORD` | Basic auth password |
| `LOGSIFT_LOKI_BEARER_TOKEN` | Bearer token auth |
| **AWS CloudWatch Logs** | |
| `LOGSIFT_CW_REGION` | AWS region (e.g., `us-east-1`) |
| `LOGSIFT_CW_PROFILE` | AWS SSO/config profile name |
| `LOGSIFT_CW_LOG_GROUP_PREFIX` | Default log group prefix (e.g., `/ecs/prod/`) |

## MCP Tools

logsift exposes two tools:

### `list_log_sources`

Discover available log sources before searching.

```json
{ "provider": "loki" }
{ "provider": "cloudwatch", "prefix": "/aws/ecs" }
```

### `search_logs`

Search and reduce logs. Parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | **Required.** `cloudwatch`, `gcp`, `kubernetes`, or `loki` |
| `source` | string | Log source (namespace, log group, log name) |
| `severity_min` | string | Minimum severity: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, `CRITICAL` |
| `text_filter` | string | Substring or regex to match in message body |
| `time_range` | string | Go duration (`15m`, `1h`, `6h`, `24h`). Default: `15m` |
| `field_filters` | object | Structured filters: `service`, `host`, `namespace`, `pod`, `container`, `level` |
| `raw_query` | string | Provider-native query (LogQL, GCP filter, CloudWatch pattern) |
| `token_budget` | integer | Max output tokens. Default: `4000` |
| `severity_keywords` | string[] | Extra words that uplift INFO→WARN (e.g., `["quota", "throttle"]`) |
| `suppress_patterns` | string[] | Regex patterns to collapse into noise (e.g., `["health.check"]`) |
| `noise_threshold` | integer | Min count for noise classification. `0` = auto-detect |
| `cursor` | string | Pagination cursor from a previous call |
| `mode` | string | Output format: `text` (default) or `json` |

For detailed usage patterns and investigation workflows, see [LLM_USAGE_GUIDE.md](LLM_USAGE_GUIDE.md).

## Contributing

Contributions are welcome. The two most impactful areas are new backends and new consolidators — both use clean plugin interfaces that require no changes to core code.

### Adding a New Backend

A backend implements three methods and registers itself via `init()`. Here's the complete pattern:

**1. Create the package:**

```
backend/
  mybackend/
    mybackend.go
    mybackend_test.go
```

**2. Implement the `Backend` interface:**

```go
package mybackend

import (
    "context"
    "github.com/fulminate-io/logsift"
)

func init() {
    logsift.Register("mybackend", &myBackend{})
}

type myBackend struct{}

// Available returns true if credentials for this backend are configured.
func (b *myBackend) Available(creds *logsift.Credentials) bool {
    return creds != nil && creds.MyBackendAPIKey != ""
}

// Search translates the query to native syntax, executes it, and returns
// normalized LogEntry structs.
func (b *myBackend) Search(ctx context.Context, creds *logsift.Credentials, q *logsift.Query) (*logsift.RawResults, error) {
    // 1. Build native query from q.Source, q.TextFilter, q.SeverityMin, etc.
    // 2. Execute against your provider's API (respect ctx for cancellation)
    // 3. Normalize results into []logsift.LogEntry
    // 4. Stop at q.MaxRawEntries
    return &logsift.RawResults{
        Entries:       entries,
        TotalEstimate: len(entries),
    }, nil
}

// ListSources returns available log sources (up to 100).
func (b *myBackend) ListSources(ctx context.Context, creds *logsift.Credentials, prefix string) ([]logsift.SourceInfo, error) {
    // Return log groups, indices, namespaces, etc.
    return sources, nil
}
```

**3. Add credential fields** to `Credentials` in `types.go`:

```go
MyBackendAPIKey  string
MyBackendRegion  string
```

**4. Wire up env vars** in `cmd/logsift/main.go` `buildCredentials()`:

```go
if key := os.Getenv("LOGSIFT_MYBACKEND_API_KEY"); key != "" {
    creds.MyBackendAPIKey = key
}
```

**5. Add the blank import** in `cmd/logsift/main.go`:

```go
_ "github.com/fulminate-io/logsift/backend/mybackend"
```

**6. Write tests.** See `backend/cloudwatch/cloudwatch_test.go` for the pattern — table-driven tests for log message parsing and field extraction.

**That's it.** The MCP tool descriptions, provider enum, and `search_logs`/`list_log_sources` dispatch all update automatically at runtime.

### Adding a New Consolidator

A consolidator recognizes language-specific patterns in clusters and merges fragments into coherent entries. This is one of the easiest contributions — typically a single file in the `reducer/` package.

**1. Create the file:**

```
reducer/
  java.go       # your consolidator
  java_test.go  # tests
```

**2. Implement the `Consolidator` interface:**

```go
package reducer

import "github.com/fulminate-io/logsift"

func init() {
    logsift.RegisterConsolidator(&javaStackConsolidator{})
}

type javaStackConsolidator struct{}

func (c *javaStackConsolidator) Name() string     { return "java_stack" }
func (c *javaStackConsolidator) Priority() int     { return 15 }  // lower = runs first
func (c *javaStackConsolidator) Consolidate(clusters []logsift.Cluster) []logsift.Cluster {
    // 1. Scan clusters: separate stack fragments from normal logs
    // 2. Sort fragments by LastSeen
    // 3. Group temporally close fragments (within 5s)
    // 4. Merge groups of 3+ fragments into a single cluster
    // 5. Return merged + unchanged clusters
}
```

The existing consolidators are good references:
- `reducer/gostack.go` — Go goroutine dumps (30s temporal window, 3+ fragment threshold)
- `reducer/python.go` — Python tracebacks (5s window, 8 regex patterns)
- `reducer/keywords.go` — Keyword severity uplift (simplest example)

**3. No other changes needed.** The `reducer` package is already blank-imported; your `init()` function runs automatically.

### General Guidelines

- Open an issue before starting work on a new backend — helps avoid duplicate effort and lets us discuss the approach
- All code must pass `go test ./... -count=1`
- Follow existing patterns — look at how current backends and consolidators are structured
- Tests should be table-driven with realistic log samples
- Keep dependencies minimal — prefer the standard library where possible

### Ideas for Contributions

Beyond backends and consolidators:

- **Reducer improvements** — Better noise detection, smarter Drain parameters, new consolidator types
- **Output formats** — SARIF, structured markdown, other LLM-friendly formats
- **Performance** — Parallel backend queries, streaming results
- **Documentation** — Provider-specific setup guides, examples, usage patterns

## Architecture

For a deeper understanding of the codebase:

```
logsift.go          — Search(), SearchRaw(), ListSources(), autoExpandWindow()
backend.go          — Backend interface, global registry
drain.go            — Drain log clustering algorithm
reduction.go        — Reduce() pipeline, Consolidator interface, dedup, sort, budget
severity.go         — Severity constants, parsing, comparison
format.go           — FormatText(), FormatJSON(), pagination cursors
types.go            — Query, LogEntry, Cluster, Credentials, ReductionResult

backend/
  gcp/              — GCP Cloud Logging (Advanced Logs Filter)
  kubernetes/       — Kubernetes pod logs (client-go)
  loki/             — Grafana Loki (LogQL over HTTP)
  cloudwatch/       — AWS CloudWatch Logs (FilterLogEvents)

reducer/
  gostack.go        — Go runtime crash consolidator
  python.go         — Python traceback consolidator
  keywords.go       — Keyword severity uplift
  structural.go     — Structural/config dump consolidator

mcpserver/
  protocol.go       — JSON-RPC 2.0 types for MCP

cmd/logsift/        — CLI entry point, MCP request handling, env var wiring
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
