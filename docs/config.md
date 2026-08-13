# Configuration

This document describes configuration for `treetop-server`.

## Overview

The server uses command-line flags and environment variables. It does not use a configuration file.
The standalone [treetop-cli](https://github.com/terjekv/treetop-cli) has its own configuration
documentation and release lifecycle.

## Server configuration

The server uses **command-line flags** and **environment variables**. There is **no server config file**.

### Server option precedence

1. Command-line flags
2. Environment variables
3. Built-in defaults

### Options

| Flag | Environment variable | Default | Description |
| --- | --- | --- | --- |
| `--host` | `TREETOP_LISTEN` | `127.0.0.1` | IP address to bind the server to. |
| `--port` | `TREETOP_PORT` | `9999` | Port to listen on. |
| `--workers` | `TREETOP_WORKERS` | auto | Number of Actix worker threads (computed from available CPUs). |
| `--rayon-threads` | `TREETOP_RAYON_THREADS` | auto | Number of Rayon worker threads for batch evaluation (computed from available CPUs). |
| `--par-threshold` | `TREETOP_PAR_THRESHOLD` | auto | Batch size threshold to enable parallel evaluation (0 or unset = auto). |
| `--allow-upload` | `TREETOP_ALLOW_UPLOAD` | `false` | Allow uploading policies via the API. |
| `--policy-url` | `TREETOP_POLICY_URL` | _(none)_ | URL to fetch policies from (Cedar). |
| `--update-frequency` | `TREETOP_POLICY_UPDATE_FREQUENCY` | _(none → 60s)_ | Poll interval for `TREETOP_POLICY_URL`. |
| `--labels-url` | `TREETOP_LABELS_URL` | _(none)_ | URL to fetch labels from (JSON). |
| `--labels-refresh` | `TREETOP_LABELS_UPDATE_FREQUENCY` | _(none → 60s)_ | Poll interval for `TREETOP_LABELS_URL`. |
| `--schema-url` | `TREETOP_SCHEMA_URL` | _(none)_ | URL to fetch Cedar schema from (JSON). |
| `--schema-refresh` | `TREETOP_SCHEMA_UPDATE_FREQUENCY` | _(none → 60s)_ | Poll interval for `TREETOP_SCHEMA_URL`. |
| `--schema-validation-mode` | `TREETOP_SCHEMA_VALIDATION_MODE` | `permissive` | Schema enforcement mode (`permissive` or `strict`) for policy/schema reloads. |
| `--max-context-bytes` | `TREETOP_MAX_CONTEXT_BYTES` | `16384` | Maximum `/api/v1/authorize` request context payload size in bytes. |
| `--max-context-depth` | `TREETOP_MAX_CONTEXT_DEPTH` | `8` | Maximum nesting depth for `/api/v1/authorize` request context values. |
| `--max-context-keys` | `TREETOP_MAX_CONTEXT_KEYS` | `64` | Maximum number of top-level `/api/v1/authorize` request context keys. |
| `--max-batch-size` | `TREETOP_MAX_BATCH_SIZE` | `1024` | Maximum authorization checks accepted in one request. |
| `--trust-ip-headers` | `TREETOP_TRUST_IP_HEADERS` | `true` | Trust proxy headers (`X-Forwarded-For`, `Forwarded`). |
| `--client-allowlist` | `TREETOP_CLIENT_ALLOWLIST` | `127.0.0.1,::1` | Allowed client IPs/CIDRs. Use `*` to allow all. |
| `--max-request-size` | `TREETOP_MAX_REQUEST_SIZE` | `10485760` | Maximum request body size in bytes. |
| `--version` | _(none)_ | `false` | Print version information and exit. |

#### Notes

- If `--policy-url` or `--labels-url` is provided, the server polls every 60 seconds unless the corresponding refresh
value is set.
- If `--schema-url` is provided, the server polls every 60 seconds unless `--schema-refresh` is set.
- The context limit settings apply to the optional `context` object accepted by `POST /api/v1/authorize`.
- The batch size limit applies to the `requests` array accepted by `POST /api/v1/authorize`; larger batches receive
  `400 Bad Request` before policy evaluation begins.
- The client allowlist accepts comma-separated IPv4/IPv6 addresses or CIDRs. Use `*` to allow all.
- Histogram boundaries are intentionally fixed across server instances rather than configurable. Native histogram
  selection is controlled by Prometheus content negotiation and scrape settings; see
  [the metrics API reference](api.md#get-metrics).

## Summary

Server configuration comes from flags, then environment variables, then built-in defaults. For CLI
configuration—including `--server-url`, config/history paths, and legacy host/port migration—see the
[standalone CLI configuration guide](https://github.com/terjekv/treetop-cli/blob/main/docs/config.md).
