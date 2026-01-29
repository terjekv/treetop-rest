# Configuration

This document describes configuration for **server** (treetop-server) and **client** (treetop-cli / REPL).

## Overview

There are **two distinct configuration surfaces**:

- **Server configuration**: runtime settings for the REST API server.
- **Client configuration**: user preferences for the CLI/REPL output.

They are independent and use different sources.

## Server configuration (treetop-server)

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
| `--workers` | `TREETOP_WORKERS` | `4` | Number of worker threads. |
| `--allow-upload` | `TREETOP_ALLOW_UPLOAD` | `false` | Allow uploading policies via the API. |
| `--policy-url` | `TREETOP_POLICY_URL` | _(none)_ | URL to fetch policies from (Cedar). |
| `--update-frequency` | `TREETOP_POLICY_UPDATE_FREQUENCY` | _(none → 60s)_ | Poll interval for `TREETOP_POLICY_URL`. |
| `--labels-url` | `TREETOP_LABELS_URL` | _(none)_ | URL to fetch labels from (JSON). |
| `--labels-refresh` | `TREETOP_LABELS_UPDATE_FREQUENCY` | _(none → 60s)_ | Poll interval for `TREETOP_LABELS_URL`. |
| `--trust-ip-headers` | `TREETOP_TRUST_IP_HEADERS` | `true` | Trust proxy headers (`X-Forwarded-For`, `Forwarded`). |
| `--client-allowlist` | `TREETOP_CLIENT_ALLOWLIST` | `127.0.0.1,::1` | Allowed client IPs/CIDRs. Use `*` to allow all. |
| `--version` | _(none)_ | `false` | Print version information and exit. |

#### Notes

- If `--policy-url` or `--labels-url` is provided, the server polls every 60 seconds unless the corresponding refresh
value is set.
- The client allowlist accepts comma-separated IPv4/IPv6 addresses or CIDRs. Use `*` to allow all.

## Client configuration (treetop-cli / REPL)

The CLI supports a **config file** for user preferences and defaults. It is separate from server configuration.

### Client option precedence

1. Command-line flags
2. Environment variables
3. Config file
4. Built-in defaults

### Config file location

The CLI config file uses the platform-standard config directory:

- **macOS**: `~/Library/Application Support/treetop-cli/config.toml`
- **Linux**: `~/.config/treetop-cli/config.toml`
- **Windows**: `%APPDATA%/treetop-cli/config.toml`

### Config file format (TOML)

The CLI config file supports **all top-level CLI switches** as keys:

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | `"127.0.0.1"` | Server host to connect to. |
| `port` | number | `9999` | Server port to connect to. |
| `json` | boolean | `false` | Print JSON responses. |
| `debug` | boolean | `false` | Print JSON requests and responses (superset of `json`). |
| `timing` | boolean | `false` | Print command execution timing. |
| `table_style` | string | `"rounded"` | Default table style. One of `rounded`, `ascii`, `unicode`, `markdown`. |

Example:

```toml
# ~/.config/treetop-cli/config.toml
host = "127.0.0.1"
port = 9999
json = false
debug = false
timing = false
table_style = "unicode"
```

### Related environment variables

These CLI options can also be set via environment variables:

- `TREETOP_CLI_SERVER_ADDRESS`
- `TREETOP_CLI_SERVER_PORT`
- `TREETOP_CLI_JSON`
- `TREETOP_CLI_DEBUG`
- `TREETOP_CLI_TIMING`
- `TREETOP_CLI_TABLE_STYLE`

## Summary

- **Server config**: flags + env vars only.
- **Client config**: TOML file + flags + env vars.

Keep them separate to avoid confusion, especially when automating deployments vs. personal CLI preferences.
