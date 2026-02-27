# logsift — LLM Usage Guide

This guide helps LLMs (and humans) use the logsift MCP tools effectively for log investigation.

## Tools

### `list_log_sources`

Discover available log sources before searching.

```json
{ "provider": "loki" }
{ "provider": "loki", "prefix": "llama" }
{ "provider": "cloudwatch" }
{ "provider": "cloudwatch", "prefix": "/llamacloud" }
```

### `search_logs`

Search and analyze logs. Returns clustered, deduplicated results sorted by signal strength.

## Basic Usage

**Start broad, then narrow:**

```json
{ "provider": "loki", "source": "my-namespace", "time_range": "1h" }
```

**Filter by severity to focus on problems:**

```json
{ "provider": "loki", "source": "my-namespace", "severity_min": "ERROR" }
```

**Search for specific text:**

```json
{ "provider": "loki", "source": "my-namespace", "text_filter": "timeout" }
```

## Understanding Results

Results are clustered log entries, not raw lines. Each cluster represents a pattern:

```
!! ERROR [x25, 12:03-12:15] Connection timeout after <*>ms
  -> Connection timeout after 3200ms
  -> Connection timeout after 5100ms

! WARN [x8, 12:05-12:10] Request validation error

  INFO [x1140, 12:00-12:15] processing http request
```

**Reading the format:**
- `!!` = ERROR/CRITICAL, `!` = WARN, blank = INFO/DEBUG
- `[x25, 12:03-12:15]` = 25 occurrences, time range
- Template line shows the pattern with `<*>` for variable parts
- `->` lines show concrete examples (only when template has wildcards)
- Footer shows `[tokens_used/budget tokens]` and optional `[cursor: ...]` for pagination

**Signal ordering:** Clusters are sorted by severity (errors first), then by occurrence count bucket, then by recency. High-frequency low-signal patterns (like per-request access logs) are demoted to the bottom.

## Reducer Tuning Parameters

These optional parameters let you tune the reduction pipeline for specific investigations.

### `severity_keywords` — Domain-Specific Severity Uplift

The reducer automatically uplifts INFO logs to WARN when they contain universal failure words (error, fail, timeout, crash, etc.). Use `severity_keywords` to add domain-specific terms:

```json
{
  "provider": "loki",
  "source": "my-api",
  "severity_keywords": ["quota", "throttle", "rate limit", "circuit breaker"]
}
```

This makes clusters containing these words sort alongside warnings instead of being buried in INFO noise.

### `suppress_patterns` — Collapse Known Noise

Regex patterns that force-classify matching clusters as noise. Noise clusters are moved to the bottom and displayed without examples, freeing token budget for signal.

```json
{
  "provider": "loki",
  "source": "my-api",
  "suppress_patterns": ["health.check", "readiness.probe", "metrics.scrape"]
}
```

Use this when you know certain patterns are uninteresting for your current investigation.

### `noise_threshold` — Override Noise Auto-Detection

By default, the reducer auto-detects noise by finding clusters with occurrence counts far above the median (10x) that have short, generic, non-negative messages. Override the count threshold:

```json
{
  "provider": "loki",
  "source": "my-api",
  "noise_threshold": 100
}
```

Set to a high value to suppress more aggressively, or omit (0) for auto-detection.

### `token_budget` — Control Output Size

Default is 4000 tokens. Increase for more detail, decrease for a tighter summary:

```json
{ "provider": "loki", "source": "my-api", "token_budget": 8000 }
```

## Investigation Patterns

### Triage — "What's wrong?"

Start with errors across a broad time range:

```json
{ "provider": "loki", "source": "my-api", "severity_min": "ERROR", "time_range": "6h" }
```

### Narrow — "When did it start?"

Search for the specific error pattern with a longer window:

```json
{ "provider": "loki", "source": "my-api", "text_filter": "connection timeout", "time_range": "24h" }
```

### Correlate — "Is it happening elsewhere?"

Check related services for the same timeframe:

```json
{ "provider": "loki", "source": "my-database", "severity_min": "WARN", "time_range": "1h" }
```

### Deep dive — "Show me everything"

Lower severity to see the full picture. Use suppress to filter known noise:

```json
{
  "provider": "loki",
  "source": "my-api",
  "severity_min": "DEBUG",
  "time_range": "15m",
  "suppress_patterns": ["health.check", "metrics"],
  "token_budget": 8000
}
```

### Paginate — "There's more?"

When results show `[cursor: ...]`, pass it to get the next page:

```json
{ "provider": "loki", "source": "my-api", "cursor": "eyJwIjoibG9raS..." }
```

## Field Filters

Use `field_filters` for structured filtering. Fields are mapped to provider-native labels:

```json
{
  "provider": "loki",
  "source": "my-namespace",
  "field_filters": {
    "container": "api-server",
    "pod": "api-server-abc123"
  }
}
```

Available fields: `service`, `host`, `namespace`, `pod`, `container`, `level`.

## Provider-Specific Notes

### CloudWatch

**Source**: The `source` parameter is the full CloudWatch log group name (path):

```json
{ "provider": "cloudwatch", "source": "/llamacloud/platform-staging/application", "time_range": "1h" }
```

If `LOGSIFT_CW_LOG_GROUP_PREFIX` is set (e.g., `/llamacloud/platform-staging/`), you can use a short name:

```json
{ "provider": "cloudwatch", "source": "application", "time_range": "1h" }
```

**Listing log groups**: Use `list_log_sources` with an optional prefix to discover available log groups:

```json
{ "provider": "cloudwatch" }
{ "provider": "cloudwatch", "prefix": "/llamacloud" }
```

**Common log groups**:
- `/llamacloud/<env>/application` — Main application logs (JSON structured, Python structlog)
- `/aws/rds/cluster/<cluster>/postgresql` — RDS PostgreSQL logs (plain text)
- `/aws/eks/<cluster>/cluster` — EKS control plane audit logs (K8s audit JSON)

**Log format handling**: CloudWatch log formats vary widely. The backend automatically handles:
- Pure JSON (`{"level":"error","msg":"..."}`)
- Logger-prefixed JSON (`[logger.name] {"event":"...","level":"warning"}`)
- Severity-prefixed text (`ERROR some message`)
- Severity + logger + JSON (`INFO [logger.name] {"event":"..."}`)
- Plain text (PostgreSQL, custom formats)

### Loki

**Source**: The `source` parameter maps to Kubernetes `namespace`:

```json
{ "provider": "loki", "source": "my-namespace", "time_range": "1h" }
```

### GCP / Kubernetes

**Source**: Log name (GCP) or namespace (Kubernetes).

## Raw Queries

For provider-native query syntax, use `raw_query`:

**CloudWatch (Filter Pattern):**
```json
{ "provider": "cloudwatch", "source": "/llamacloud/platform-staging/application", "raw_query": "{ $.level = \"error\" }" }
```

CloudWatch filter patterns: simple text (`"ERROR"`), quoted phrases (`"connection timeout"`), or JSON selectors (`{ $.level = "error" }`).

**Loki (LogQL):**
```json
{ "provider": "loki", "raw_query": "{namespace=\"my-ns\"} |= \"error\" | json | level = \"error\"" }
```

**GCP (Advanced Logs Filter):**
```json
{ "provider": "gcp", "source": "stderr", "raw_query": "resource.labels.container_name=\"api\"" }
```

**Kubernetes (label selector):**
```json
{ "provider": "kubernetes", "source": "my-ns", "raw_query": "app=api-server" }
```

## How the Reducer Works

The reduction pipeline processes raw logs through 7 layers:

1. **Severity filtering** — Drop entries below `severity_min`
2. **Exact deduplication** — Hash-based fast-path removing identical messages
3. **Drain template clustering** — Groups similar messages into patterns (e.g., `GET /api/users/<*> -> 200`)
4. **Consolidators** — Language-specific grouping (Python tracebacks, Go panics, structural fragments, JSON data dumps, negative keyword severity uplift)
5. **Stack trace grouping** — Merges related stack trace fragments
6. **Signal-first sorting** — Severity DESC, then count bucket, then recency. Noise clusters demoted to end.
7. **Token-budget truncation** — Fits output within the budget, with pagination cursor for overflow

Typical compression: **95-99%** token reduction (5,000 raw entries → 30-70 clusters in ~3,000 tokens).
