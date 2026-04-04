# Treetop REST API

This document describes the HTTP interface exposed by the Treetop REST server for
policy management and evaluation.

## Base URL and formats

- Default base URL: `http://localhost:9999`
- All requests and responses use JSON unless noted.
- Policy upload requests accept either `application/json` with a `policies` string
  field or `text/plain` containing Cedar policy DSL.
- Schema upload requests accept either `application/json` with a `schema` string
  field or `text/plain` containing Cedar schema JSON.

## Authentication

- There is (currently) no authentication for GET endpoints.
- Uploads to `/api/v1/policies` and `/api/v1/schema` require `TREETOP_ALLOW_UPLOAD=true`
  to be set on server start and the header `X-Upload-Token: <token>` matching the
  server-generated upload token. This token is printed in the server logs on startup.

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
  - `requests`: Array of authorization requests, each containing:
    - `id` (optional): Client-provided identifier for correlating responses
    - `context` (optional): request-scoped Cedar attributes passed as `context.<field>`
    - `principal`: Principal object
    - `action`: Action identifier
    - `resource`: Resource object with `kind`, `id`, and optional `attrs`
- Context behavior:
  - `context` is fully evaluated when supplied.
  - In `strict` schema mode, sending `context` without an uploaded schema fails that request.
  - In `permissive` mode, context can still be evaluated when runtime has fallen back to a schema-free engine, but `/api/v1/status.request_context` will report the fallback state.
  - Context object values must use the same `AttrValue` encoding as resource attributes. Flat strings, booleans, numbers, and arrays are accepted directly by the CLI context file loader.

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

1. **Batch Size**: For optimal performance, batch request counts per call depending on your use case and server capacity
2. **Error Handling**: Check both the HTTP status code and individual result statuses
3. **Consistency**: All requests in a batch are guaranteed to be evaluated against the same policy version
4. **Indexing**: Use the `index` field or your results to correlate responses with requests,
or use the optional `id` field for easier tracking
5. **Runtime visibility**: Inspect `/api/v1/status.request_context` to see whether evaluation is currently schema-backed or in permissive fallback mode
