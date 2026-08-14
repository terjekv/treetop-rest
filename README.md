# A REST server for Treetop

This is a REST server providing a REST API for [Treetop](https://github.com/terjekv/treetop-core),
a policy management framework.

Version 0.0.11 and later contain only the server. The bundled `treetop-cli` binary was removed after
the v0.0.10 bridge release. Install the supported standalone CLI from the
[treetop-cli repository](https://github.com/terjekv/treetop-cli); its configuration, matrix syntax,
and release binaries are documented there.

See [docs/api.md](docs/api.md) for the HTTP API reference. A running server exposes
the generated OpenAPI document at `/openapi.json` and Swagger UI at `/swagger-ui/`.
The generated specification is also checked in at [docs/openapi.json](docs/openapi.json).

## Server startup

The server supports the following environment variables:

- `TREETOP_LISTEN`: The host to bind the server to (default: `localhost`)
- `TREETOP_PORT`: The port to bind the server to (default: `9999`)
- `TREETOP_WORKERS`: The number of Actix worker threads to use (default: auto based on CPU)
- `TREETOP_RAYON_THREADS`: The number of Rayon worker threads for batch evaluation (default: auto based on CPU)
- `TREETOP_PAR_THRESHOLD`: Batch size threshold to enable parallel evaluation (default: auto based on CPU)
- `TREETOP_ALLOW_UPLOAD`: Whether to allow manually uploading policies to the server. If set to `true`,
  you can upload policies via `POST` to the `/api/v1/policies` endpoint with the content type `text/plain`.
  You will need to provide the upload token in the header `X-Upload-Token`. This token is printed in the
  logs at the `warn` level when the server starts. (default: `false`)
- `TREETOP_POLICY_URL`: An optional URL for fetching the policy file (in Cedar format) (default: `None`).
- `TREETOP_POLICY_UPDATE_FREQUENCY`: The frequency (in seconds) at which to update the policy file from the
  `TREETOP_POLICY_URL` (default: `60`).
- `TREETOP_LABELS_URL`: An optional URL for fetching the label file (in JSON format) (default: `None`).
- `TREETOP_LABELS_UPDATE_FREQUENCY`: The frequency (in seconds) at which to update the label file from the
  `TREETOP_LABELS_URL` (default: `60`).
- `TREETOP_SCHEMA_URL`: An optional URL for fetching a Cedar schema (default: `None`).
- `TREETOP_SCHEMA_UPDATE_FREQUENCY`: The frequency (in seconds) at which to update the schema from the
  `TREETOP_SCHEMA_URL` (default: `60`).
- `TREETOP_SCHEMA_VALIDATION_MODE`: Schema mode for policy/schema reloads: `permissive` or `strict`
  (default: `permissive`).
- `TREETOP_CLIENT_ALLOWLIST`: Whitelist of client IPs or CIDR blocks. Use `*` to allow all,
  or comma-separated IPv4/IPv6 addresses/CIDRs (default: `127.0.0.1,::1`).
- `TREETOP_TRUST_IP_HEADERS`: Whether to trust proxy IP headers (`X-Forwarded-For`, `Forwarded`).
  If `false`, only uses peer address (default: `true`).
- `TREETOP_MAX_CONTEXT_BYTES`: Maximum request context payload size in bytes (default: `16384`).
- `TREETOP_MAX_CONTEXT_DEPTH`: Maximum request context nesting depth (default: `8`).
- `TREETOP_MAX_CONTEXT_KEYS`: Maximum number of top-level request context keys (default: `64`).
- `TREETOP_MAX_BATCH_SIZE`: Maximum number of authorization checks accepted in one request (default: `1024`).
- `TREETOP_MAX_REQUEST_SIZE`: Maximum request body size in bytes (default: `10485760` = 10 MB).

### Client interaction

From the command line, you can use `curl` to interact with the API. For example, to upload a policy file, you can use:

```bash
curl -X POST http://localhost:9999/api/v1/policies -H "Content-Type: text/plain" -H "X-Upload-Token: <your-upload-token>" --data-binary @testdata/default.cedar
```

To check a request, you can use:

```bash
$ curl -X POST 'http://localhost:9999/api/v1/authorize?detail=brief' \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "principal": { "User": { "id": "alice", "namespace": ["DNS"], "groups": [{ "id": "admins", "namespace": ["DNS"] }] } },
        "action": { "id": "create_host", "namespace": ["DNS"] },
        "resource": {
          "kind": "Host",
          "id": "hostname.example.com",
          "attrs": {
            "name": { "type": "String", "value": "hostname.example.com" },
            "ip": { "type": "Ip", "value": "10.0.0.1" }
          }
        }
      }
    ]
  }'
```

To check a request with request-scoped context, include a `context` object:

```bash
$ curl -X POST 'http://localhost:9999/api/v1/authorize?detail=brief' \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "context": {
          "env": { "type": "String", "value": "prod" }
        },
        "principal": { "User": { "id": "alice", "namespace": ["DNS"], "groups": [{ "id": "admins", "namespace": ["DNS"] }] } },
        "action": { "id": "create_host", "namespace": ["DNS"] },
        "resource": {
          "kind": "Host",
          "id": "hostname.example.com",
          "attrs": {
            "name": { "type": "String", "value": "hostname.example.com" },
            "ip": { "type": "Ip", "value": "10.0.0.1" }
          }
        }
      }
    ]
  }'
```

For typed command-line access, interactive REPL support, configuration migration details, and
matrix queries, use [treetop-cli](https://github.com/terjekv/treetop-cli). Version 0.0.1 depends
exactly on `treetop-client` 0.0.2 and is the migration target for the CLI bundled in REST v0.0.10.

## Metrics and performance

`GET /metrics` exposes OpenMetrics text with backward-compatible classic histogram series. Prometheus can negotiate
protobuf to ingest adaptive native histograms. Latency is available at four distinct levels:

- server-side HTTP handling in `http_request_duration_seconds`;
- accepted authorization-request handling by bounded batch-size class in
  `authorization_request_duration_seconds`, paired with the `authorization_batch_size` distribution;
- total Treetop Core evaluation in `policy_eval_duration_seconds`;
- label, entity, group, Cedar authorization, and residual Core phases in
  `policy_eval_phase_duration_seconds`.

The classic layout includes boundaries from 10 microseconds through 10 seconds, while native histograms adapt across
workload distributions. See the [metrics API reference](docs/api.md#get-metrics) for labels, bucket and series cost,
Prometheus scrape configuration, PromQL examples, and migration notes.

For repeatable client-observed HTTP throughput/latency and the matching Core phase means, run the opt-in release-mode
characterization documented in [docs/performance.md](docs/performance.md). It can export a reviewable JSON report for
voluntary machine-anonymous result sharing, including CPU/OS setup and REST/Core/Cedar version and source provenance but
no automatic telemetry. The included Linux matrix runner defaults to real 1-, 2-, 4-, and 8-CPU allocations, accepts
arbitrary counts or exact CPU sets, and can compare production, HTTP-heavy, batch-heavy, and combined thread layouts. A
separate k6 scenario covers sustained, fixed-arrival-rate, and remote load while keeping result publication opt-in.

## Development

There is also a `docker-compose.yml` to set up a minialist web server to host cedar policies.
This will automatically set up a web server hosting the `testdata` folder.
Currently, this will `http://localhost:8080/default.cedar` and `http://localhost:8080/labels.json`.

```bash
docker-compose up
```
