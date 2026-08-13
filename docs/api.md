# Treetop REST API

This document describes the HTTP interface exposed by the Treetop REST server for
policy management and evaluation.

## Base URL and formats

- Default base URL: `http://localhost:9999`
- All requests and responses use JSON unless noted.
- Policy upload requests accept either `application/json` with a `policies` string
  field or `text/plain` containing Cedar policy DSL.
- Schema upload requests accept `application/json` containing either a `schema`
  string field or a raw Cedar schema document, or `text/plain` containing Cedar
  schema JSON.

## Authentication

- There is (currently) no authentication for GET endpoints.
- Uploads to `/api/v1/policies` and `/api/v1/schema` require `TREETOP_ALLOW_UPLOAD=true`
  to be set on server start and the header `X-Upload-Token: <token>` matching the
  server-generated upload token. This token is printed in the server logs on startup.

## Errors

Fallible endpoints return a JSON object with an `error` message and stable `code`.
Parse and schema errors may also include `details` containing `line` and `column`
numbers when the underlying parser reports them.

## Endpoints

### GET /livez

- Purpose: Kubernetes-style liveness probe. A successful response means the HTTP
  worker is alive; the probe deliberately does not depend on remote configuration.
- Response: `ok` as plain text with HTTP 200.
- This operational endpoint bypasses the client IP allowlist so an orchestrator can
  probe it from outside the API allowlist.

### GET /readyz

- Purpose: Kubernetes-style readiness probe. A successful response means the policy
  store is available and every configured remote policy, labels, and schema source
  has completed at least one valid load.
- Response: `ok` as plain text with HTTP 200 when ready, or `not ready` with HTTP 503.
- The check does not make network requests. After an initial successful load, a later
  remote fetch failure continues serving the last-known-good configuration and does
  not make the service unready.
- This operational endpoint bypasses the client IP allowlist so an orchestrator can
  probe it from outside the API allowlist.

### GET /openapi.json

- Purpose: machine-readable OpenAPI specification generated from the server route
  definitions.
- Response: OpenAPI JSON document for the Treetop REST API.
- Interactive documentation: Swagger UI is available at `/swagger-ui/` and loads
  this canonical document.
- Compatibility: `/api-docs/openapi.json` serves the same document for clients of
  earlier releases.
- Static copy: [`docs/openapi.json`](openapi.json). Regenerate it with
  `cargo run --example openapi > docs/openapi.json`.

### GET /metrics

- Purpose: Prometheus/OpenMetrics counters, gauges, and latency histograms.
- Default response: OpenMetrics 1.0 text with
  `Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8`.
- Native histogram response: length-delimited Prometheus `MetricFamily` protobuf when the `Accept` header requests
  `application/vnd.google.protobuf`, `proto=io.prometheus.client.MetricFamily`, and `encoding=delimited`.
- This operational endpoint is subject to the configured client IP allowlist.

The server exposes classic and native representations of both latency histograms. The metric sample names and label
keys used before this migration are retained:

| Metric | Labels | Meaning |
| --- | --- | --- |
| `http_requests_total` | `method`, `path`, `status_code`, `client_ip` | Completed HTTP requests. |
| `http_request_duration_seconds` | `method`, `path`, `status_code` | Server-side HTTP handling time. |
| `policy_evals_total` | `action` | Core policy decisions. |
| `policy_evals_allowed_total` | `action` | Allowed Core decisions. |
| `policy_evals_denied_total` | `action` | Denied Core decisions. |
| `policy_eval_duration_seconds` | `action` | Total Treetop Core evaluation time per decision. |
| `policy_eval_phase_duration_seconds` | `action`, `phase` | One Core phase per decision. |
| `policy_reloads_total` | none | Successful Core policy reloads. |
| `schema_reloads_total` | none | Successful schema reloads. |
| `schema_validation_failures_total` | `reason` | Schema validation failures. |
| `context_validation_failures_total` | `reason` | Request-context validation failures. |
| `treetop_build_info` | `app_version`, `core_version`, `cedar_version` | Build identity gauge fixed at 1. |

HTTP `path` uses the registered route template, such as `/api/v1/policies/{user}`, rather than the raw user value.
Requests that do not match a registered route use `path="unmatched"`. This bounds path cardinality. `client_ip` remains
on the request counter for compatibility but is deliberately absent from the duration histogram.

The action label is the Cedar entity UID without representation quotes, for example `Action::view`. Treat the action
vocabulary as a controlled, bounded set. Percent, quote, backslash, and control characters inside unusual action IDs
use uppercase percent encoding to keep text and protobuf labels identical and collision-safe. Dynamic per-request action
IDs would create high-cardinality metrics.

#### Policy phase semantics

`policy_eval_phase_duration_seconds` builds directly on the phase timings exported by Treetop Core 0.0.19:

| `phase` | Timing boundary |
| --- | --- |
| `apply_labels` | Apply configured labels to the request resource. |
| `construct_entities` | Build Cedar entities used for evaluation. |
| `resolve_groups` | Resolve principal group entities. |
| `cedar_authorize` | Call Cedar's `Authorizer::is_authorized`. |
| `overhead` | Non-negative residual of Core total minus the four named phases. |

The residual currently includes Cedar request construction, result and diagnostic materialization, other unpartitioned
Core work, and timer precision. If a future optimization requires another internal boundary, add it to Treetop Core's
`EvaluationPhases` first and then expose it here; the REST server does not duplicate Core timers.

One HTTP authorization batch produces one HTTP observation and one total plus five phase observations per decision.
Batch decisions can execute concurrently. Consequently, the HTTP duration is not the sum of policy durations, and the
sum of phase percentiles is not a total percentile. Compare sums or means when estimating phase contribution.

The opt-in [performance characterization](performance.md) reports the wider client-observed HTTP round trip alongside
these server and Core layers.

#### Histogram layout

OpenMetrics text exposes these 19 finite classic boundaries, in seconds:

```text
0.000010, 0.000025, 0.000050, 0.000100, 0.000250, 0.000500,
0.001, 0.0025, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250,
0.500, 1, 2.5, 5, 10
```

The layout is a strict superset of the former Prometheus client defaults. It preserves every old boundary while adding
10, 25, 50, 100, 250, and 500 microsecond buckets plus 1 and 2.5 millisecond buckets. This resolves the normal
Treetop distribution without sacrificing the previous long-tail coverage.

Each populated classic label set costs 20 bucket series including `+Inf`, plus `_sum` and `_count`: 22 series instead
of the previous 14, a 57% increase. The phase metric can populate five label sets per observed action, or 110 classic
series per action. HTTP series scale with observed `method`/route-template/`status_code` combinations. Native ingestion
uses one sparse histogram series per label set and is the preferred long-term representation for varied workloads.

The protobuf response also contains a standard exponential native histogram with a maximum bucket growth factor of
1.1 and an instrumentation-side best-effort limit of 160 populated sparse buckets. Native buckets adapt to distributions
outside the classic range without a server configuration matrix. The fixed classic layout remains fleet-wide so
classic histograms are aggregatable during migration.

#### Enable native histogram scraping

[Prometheus 3.8 and newer](https://prometheus.io/docs/specs/native_histograms/) support native histograms as a stable
feature, but Prometheus 3.x still requires explicit scrape configuration. During migration, ingest both forms so
existing classic queries continue working:

```yaml
scrape_configs:
  - job_name: treetop-rest
    scrape_native_histograms: true
    always_scrape_classic_histograms: true
    static_configs:
      - targets: ["treetop-rest:9999"]
```

After dashboards, alerts, recording rules, and the longest relevant query window use native histograms, set
`always_scrape_classic_histograms: false` to avoid storing the classic bucket series. Prometheus then negotiates the
protobuf response and retains the native part. If remote write is used, configure its native-histogram support as well.
See the [Prometheus native histogram specification](https://prometheus.io/docs/specs/native_histograms/) for versioned
scrape and remote-write requirements.

No Treetop server flag selects the exposition: ordinary text scrapers receive the compatibility form, while Prometheus
content negotiation selects protobuf. A direct protobuf request is:

```bash
curl -H 'Accept: application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited' \
  http://localhost:9999/metrics --output metrics.pb
```

#### PromQL examples

Native histogram p95 HTTP latency by route:

```promql
histogram_quantile(
  0.95,
  sum by (path) (rate(http_request_duration_seconds[5m]))
)
```

Native histogram p95 Core phase latency:

```promql
histogram_quantile(
  0.95,
  sum by (action, phase) (rate(policy_eval_phase_duration_seconds[5m]))
)
```

Native histogram mean phase time uses `histogram_sum` and `histogram_count`:

```promql
sum by (action, phase) (
  histogram_sum(rate(policy_eval_phase_duration_seconds[5m]))
)
/
sum by (action, phase) (
  histogram_count(rate(policy_eval_phase_duration_seconds[5m]))
)
```

The equivalent classic p95 query keeps the `le` dimension:

```promql
histogram_quantile(
  0.95,
  sum by (le, path) (rate(http_request_duration_seconds_bucket[5m]))
)
```

#### Migration notes

- Metric sample names and label keys are unchanged. Existing exact queries for old classic boundaries continue to use
  the same time series.
- `/metrics` text changes from Prometheus 0.0.4 to OpenMetrics 1.0 and ends with `# EOF`. Counter `TYPE` metadata uses
  the OpenMetrics family name without `_total`; counter sample names still end in `_total`.
- Action label values change from Cedar's quoted display form, such as `Action::\"view\"`, to `Action::view`.
- Raw HTTP paths change to route templates, and unmatched requests collapse to `unmatched`. Update dashboards that
  selected a concrete `/api/v1/policies/<user>` path.
- Newly added classic buckets and all native histogram series have no pre-deployment history. Avoid aggregating classic
  quantiles across mixed old/new instances or a range spanning the rollout; wait at least one full query window after
  every target uses the new layout.
- Native and classic histogram samples are different Prometheus data types. During dual ingestion, keep their queries
  separate; do not add them together.

### GET /api/v1/health

- Purpose: legacy liveness probe retained for compatibility. New deployments should
  use `/livez` and `/readyz`.
- Response: `{}` with HTTP 200.

### GET /api/v1/version

- Purpose: version metadata for the server and policy engine.
- Response shape:
  - `version`: server version string.
  - `core`: `{ version, cedar }` identifying treetop-core and Cedar versions.
  - `policies`: `{ hash, loaded_at }` identifying the currently loaded policy set.
     The hash is a SHA-256 of the policy content, and `loaded_at` is an RFC 3339
     timestamp of when the policies were loaded.
  - `schema` (optional): `{ hash, loaded_at }` identifying the currently loaded schema.

Example response:

```json
{
  "version": "0.1.0",
  "core": {
    "version": "0.3.0",
    "cedar": "0.11.0"
  },
  "policies": {
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  }
}
```

### GET /api/v1/status

- Purpose: server status plus metadata for currently loaded policies, labels, and schema.
- Response shape:
  - `policy_configuration`: policy, label, and schema metadata, including:
    - `allow_upload`
    - `schema_validation_mode`
    - `policies`
    - `labels`
    - `schema`
  - `parallel_configuration`: current Actix/Rayon worker settings.
  - `request_limits`: currently enforced context limits.
  - `request_context`: runtime context mode:
    - `supported`: request context is supported by the bundled core.
    - `schema_backed`: request/context evaluation is currently using a schema-backed engine.
    - `fallback_reason`: `no_schema` or `schema_incompatible` when runtime is not schema-backed.

Example response:

```json
{
  "policy_configuration": {
    "allow_upload": false,
    "schema_validation_mode": "permissive",
    "policies": {
      "timestamp": "2025-12-19T00:14:38.577289000Z",
      "sha256": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
      "size": 2049,
      "source": { "url": "https://example.com/policies.cedar" },
      "refresh_frequency": 300,
      "entries": 42,
      "content": "...DSL content..."
    },
    "labels": {
      "timestamp": "2025-12-19T00:10:00.123456000Z",
      "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
      "size": 512,
      "source": { "url": "https://example.com/labels.json" },
      "refresh_frequency": 600,
      "entries": 10,
      "content": "...JSON content..."
    },
    "schema": {
      "timestamp": "2025-12-19T00:12:00.000000000Z",
      "sha256": "bbf3d4d65ab0c11f8fa73f8cf54eb7bbd7d8bfcc8ca0d26f5cab098507ad6f6d",
      "size": 411,
      "source": null,
      "refresh_frequency": null,
      "entries": 1,
      "content": "{...schema json...}"
    }
  },
  "parallel_configuration": {
    "cpu_count": 8,
    "workers": 8,
    "rayon_threads": 8,
    "par_threshold": 8,
    "allow_parallel": true
  },
  "request_limits": {
    "max_batch_size": 1024,
    "max_context_bytes": 16384,
    "max_context_depth": 8,
    "max_context_keys": 64
  },
  "request_context": {
    "supported": true,
    "schema_backed": false,
    "fallback_reason": "no_schema"
  }
}
```

### GET /api/v1/policies

- Purpose: download the current policy set.
- Query: `format=raw` (or `text`) to receive plain DSL content; otherwise
  JSON.
- Responses:
  - JSON: `{ "policies": Metadata }` with `content` containing the DSL string.
  - Raw: `text/plain` body with the DSL.

### POST /api/v1/policies

- Purpose: upload or replace the policy set (if allowed).
- Headers: `X-Upload-Token` when upload token is configured and `Content-Type`
  as described above.

#### Upload examples

JSON:

```bash
curl -X POST http://localhost:9999/api/v1/policies \
  -H "Content-Type: application/json" \
  -H "X-Upload-Token: <token>" \
  --data-binary @policies.json
```

See the [cedar JSON documentation](https://docs.cedarpolicy.com/policies/json-format.html) for details.

Cedar DSL:

```bash
curl -X POST http://localhost:9999/api/v1/policies \
  -H "Content-Type: text/plain" \
  -H "X-Upload-Token: <token>" \
  --data-binary @policies.cedar
```

See the [Cedar policy language documentation](https://docs.cedarpolicy.com/policies/syntax-policy.html) for details.

- Response: `PoliciesMetadata` reflecting the newly loaded policies and labels. As per the
  status endpoint (minus `allow_upload`).

### GET /api/v1/schema

- Purpose: download the current Cedar schema.
- Query: `format=raw` (or `text`) to receive raw schema JSON; otherwise JSON.
- Responses:
  - JSON: `{ "schema": Metadata }` with `content` containing schema JSON.
  - Raw: `text/plain` body with schema JSON.

### POST /api/v1/schema

- Purpose: upload or replace the Cedar schema (if allowed).
- Headers: `X-Upload-Token` when upload token is configured and `Content-Type`
  as described above.
- Request body: a JSON object with a `schema` string, a raw Cedar schema JSON
  document, or the Cedar schema JSON as `text/plain`.
- Response: `PoliciesMetadata` with updated schema metadata.

### GET /api/v1/policies/{user}

- Purpose: list policies that apply to a user.
- Response: `{ "user": "<user>", "policies": [<policy_json_objects>], "matches": [<match_metadata>] }`.
  - `matches[].cedar_id`: Cedar policy identifier.
  - `matches[].reasons`: Why each policy matched (for example `PrincipalEq`, `ActionEq`, `ResourceIs`).

### POST /api/v1/authorize (Unified Authorization Endpoint)

- Purpose: evaluate one or more authorization requests with optional client-provided identifiers.
- Query parameters:
  - `detail`: Response detail level. `brief` (default) returns only decision and version; `full` (or `detailed`)
  includes matching policy information.
- Request body (JSON):
  - `requests`: Array of authorization requests. The server rejects arrays larger than its configured
    `TREETOP_MAX_BATCH_SIZE` before evaluation. Each entry contains:
    - `id` (optional): Client-provided identifier for correlating responses
    - `context` (optional): request-scoped Cedar attributes passed as `context.<field>`
    - `principal`: Principal object
    - `action`: Action identifier
    - `resource`: Resource object with `kind`, `id`, and optional `attrs`
- Context behavior:
  - `context` is fully evaluated when supplied.
  - In `strict` schema mode, sending `context` without an uploaded schema fails that request.
  - In `permissive` mode, context can still be evaluated when runtime has fallen back to a schema-free engine, but
    `/api/v1/status.request_context` will report the fallback state.
  - Context object values use the same `AttrValue` encoding as resource attributes. Flat strings, booleans,
    numbers, and arrays are accepted directly by the API model.

**Example request:**

```bash
curl -X POST http://localhost:9999/api/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "id": "check-1",
        "context": {
          "env": { "type": "String", "value": "prod" }
        },
        "principal": { "User": { "id": "alice", "namespace": ["DNS"], "groups": [{ "id": "admins", "namespace": ["DNS"] }] } },
        "action": { "id": "create_host", "namespace": ["DNS"] },
        "resource": {
          "kind": "Host",
          "id": "hostname.example.com",
          "attrs": {
            "ip":   { "type": "Ip", "value": "10.0.0.1" },
            "name": { "type": "String", "value": "hostname.example.com" }
          }
        }
      },
      {
        "id": "check-2",
        "principal": { "User": { "id": "bob", "namespace": ["Service"], "groups": [] } },
        "action": { "id": "view", "namespace": ["Service"] },
        "resource": {
          "kind": "Photo",
          "id": "photo.jpg",
          "attrs": {
            "owner": { "type": "String", "value": "alice" }
          }
        }
      }
    ]
  }'
```

**Response (brief, default):**

```json
{
  "results": [
    {
      "index": 0,
      "id": "check-1",
      "status": "success",
      "result": {
        "decision": "Allow",
        "policy_id": "default",
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 1,
      "id": "check-2",
      "status": "success",
      "result": {
        "decision": "Deny",
        "policy_id": "",
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 2,
      "id": "check-3",
      "status": "failed",
      "error": "Evaluation failed: invalid resource"
    }
  ],
  "version": {
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  },
  "successful": 2,
  "failed": 1
}
```

**Response (detailed, ?detail=full):**

```json
{
  "results": [
    {
      "index": 0,
      "id": "check-1",
      "status": "success",
      "result": {
        "policy": [
          {
            "literal": "permit (...)",
            "json": {...}
          }
        ],
        "decision": "Allow",
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 1,
      "id": "check-2",
      "status": "success",
      "result": {
        "policy": [],
        "decision": "Deny",
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    }
  ],
  "version": {
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  },
  "successful": 2,
  "failed": 0
}
```

### Features

- **Single or Multiple Requests**: Handle one or many authorization requests in a single call
- **Client Identifiers**: Optional `id` field on each request for easy correlation of responses
- **Parallel Processing**: All requests evaluated in parallel using Rayon
- **Consistent Snapshot**: All requests evaluated against the same policy version
- **Detailed or Brief Results**: Control response verbosity with the `?detail` query parameter
- **Index Tracking**: Results maintain input order with `index` field

### Performance Considerations

1. **Parallel Execution**: Requests are processed in parallel across available CPU cores using Rayon
2. **Lock Management**: The policy store lock is acquired once and released before parallel processing begins
3. **Engine Snapshot**: A snapshot of the PolicyEngine is cloned for consistent evaluation

### Best Practices

1. **Batch Size**: Keep each batch within the server's configured maximum and tune batch size for the available capacity
2. **Error Handling**: Check both the HTTP status code and individual result statuses
3. **Consistency**: All requests in a batch are guaranteed to be evaluated against the same policy version
4. **Indexing**: Use the `index` field or your results to correlate responses with requests,
or use the optional `id` field for easier tracking
5. **Runtime visibility**: Inspect `/api/v1/status.request_context` to see whether evaluation is currently schema-backed
   or in permissive fallback mode
