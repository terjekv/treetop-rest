# Treetop REST API

This document describes the HTTP interface exposed by the Treetop REST server for
policy management and evaluation.

## Base URL and formats

- Default base URL: `http://localhost:9999`
- All requests and responses use JSON unless noted.
- Upload requests accept either `application/json` with a `policies` string field
  or `text/plain` containing the Cedar policy DSL.

## Authentication

- There is (currently) no authentication for GET endpoints.
- Uploads to `/api/v1/policies` require `TREETOP_ALLOW_UPLOAD=true` to be set on server start
  and the header `X-Upload-Token: <token>` matching the server-generated upload token. This
  token is printed in the server logs on startup.

## Endpoints

### GET /api/v1/health

- Purpose: liveness probe.
- Response: `{}` with HTTP 200.

### GET /api/v1/version

- Purpose: version metadata for the server and policy engine.
- Response shape:
  - `version`: server version string.
  - `core`: `{ version, cedar }` identifying treetop-core and Cedar versions.
  - `policies`: `{ hash, loaded_at }` identifying the currently loaded policy set.
     The hash is a SHA-256 of the policy content, and `loaded_at` is an RFC 3339
     timestamp of when the policies were loaded.

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

- Purpose: server status plus metadata for currently loaded policies and labels.
- Response: `PoliciesMetadata` object with fields:
  - `allow_upload`: whether policy uploads are currently permitted.
  - `policies`: metadata for the active policy DSL (timestamp, sha256, size,
    optional source URL, optional refresh_frequency seconds, entries count,
    content).
  - `labels`: metadata for the active labels file (same shape as policies
    metadata).

Example response:

```json
{
  "allow_upload": false,
  "policies": {
    "loaded_at": "2025-12-19T00:14:38.577289000Z",
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "size": 2049,
    "source_url": "https://example.com/policies.cedar",
    "refresh_frequency": 300,
    "entries": 42,
    "content": "...DSL content..."
  },
  "labels": {
    "loaded_at": "2025-12-19T00:10:00.123456000Z",
    "hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
    "size": 512,
    "source_url": "https://example.com/labels.json",
    "refresh_frequency": 600,
    "entries": 10,
    "content": "...JSON content..."
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

### GET /api/v1/policies/{user}

- Purpose: list policies that apply to a user.
- Response: `{ "user": "<user>", "policies": [<policy_json_objects>] }`.

### POST /api/v1/authorize (Unified Authorization Endpoint)

- Purpose: evaluate one or more authorization requests with optional client-provided identifiers.
- Query parameters:
  - `detail`: Response detail level. `brief` (default) returns only decision and version; `full` (or `detailed`)
  includes matching policy information.
- Request body (JSON):
  - `requests`: Array of authorization requests, each containing:
    - `id` (optional): Client-provided identifier for correlating responses
    - `principal`: Principal object
    - `action`: Action identifier
    - `resource`: Resource object with `kind`, `id`, and optional `attrs`

**Example request:**

```bash
curl -X POST http://localhost:9999/api/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "id": "check-1",
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
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 1,
      "id": "check-2",
      "status": "failed",
      "error": "Evaluation failed: invalid resource"
    }
  ],
  "version": {
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  },
  "successful": 1,
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
        "policy": {
          "literal": "permit (...)",
          "json": {...}
        },
        "desicion": "Allow",
        "version": {
          "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 1,
      "id": "check-2",
      "status": "failed",
      "error": "Evaluation failed: invalid resource"
    }
  ],
  "version": {
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  },
  "successful": 1,
  "failed": 1
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

1. **Batch Size**: For optimal performance, batch request counts per call depending on your use case and server capacity
2. **Error Handling**: Check both the HTTP status code and individual result statuses
3. **Consistency**: All requests in a batch are guaranteed to be evaluated against the same policy version
4. **Indexing**: Use the `index` field or your results to correlate responses with requests, or use the optional `id` field for easier tracking
