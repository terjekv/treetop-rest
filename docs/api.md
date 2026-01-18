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
- Uploads to `/api/v1/policies` require `APP_ALLOW_UPLOAD=true` to be set on server start
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

### POST /api/v1/check

- Purpose: evaluate a request and return an allow/deny decision.
- Request body (JSON):
  - `principal`: principal object supported by treetop-core (namespaces
    optional).
  - `action`: action identifier (namespaces optional).
  - `resource`: `{ kind, id, attrs? }` with optional `attrs` map. Supported
    attribute value types: `String`, `Int`, `Bool`, `Ip`, `Set`.

- Response shape:
  - `decision`: `Allow` or `Deny`.
  - `version`: `PolicyVersion` identifying the policy set used for the decision.

Example request:

```bash
curl -X POST http://localhost:9999/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

Example response:

```json
{
  "decision": "Allow",
  "version": {
    "hash": "...",
    "updated": "2025-12-16T22:04:47.321459Z"
  }
}
```

### POST /api/v1/check_detailed

Same request structure as `/api/v1/check` but returns the matching policy if the decision is `Allow`.

- Response shape:
  - `policy`: `PermitPolicy` when decision is `Allow`, otherwise `null`.
  - `desicion`: `Allow` or `Deny` (field name is intentionally misspelled).
  - `version`: `PolicyVersion` identifying the policy set used for the decision.

Example response:

```json
{
  "policy": {
    "literal": "@id(\"DNS.admins_policy\")\npermit (\n    principal in DNS::Group::\"admins\",\n    action in\n        [DNS::Action::\"create_host\",\n         DNS::Action::\"delete_host\",\n         DNS::Action::\"view_host\",\n         DNS::Action::\"edit_host\"],\n    resource is Host\n);",
    "json": {
      "effect": "permit",
      "principal": {
        "op": "in",
        "entity": {
          "type": "DNS::Group",
          "id": "admins"
        }
      },
      "action": {
        "op": "in",
        "entities": [
          {
            "type": "DNS::Action",
            "id": "create_host"
          },
          {
            "type": "DNS::Action",
            "id": "delete_host"
          },
          {
            "type": "DNS::Action",
            "id": "view_host"
          },
          {
            "type": "DNS::Action",
            "id": "edit_host"
          }
        ]
      },
      "resource": {
        "op": "is",
        "entity_type": "Host"
      },
      "conditions": [],
      "annotations": {
        "id": "DNS.admins_policy"
      }
    }
  },
  "version": {
    "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  }
}
```

## Batch API

The batch API allows you to evaluate multiple authorization requests in a single HTTP call with parallel processing
on the server side.

### Features

- **Parallel Processing**: All requests are evaluated in parallel using Rayon for maximum throughput
- **Consistent Snapshot**: All requests in a batch are evaluated against the same policy version
- **Individual Results**: Each request's result is tracked separately with success/failure status
- **Index Tracking**: Results maintain the same order as the input requests with explicit index values

### POST /api/v1/batch_check - Brief Results

Process multiple authorization requests and return brief results (decision + version only).

**Request:**

```json
{
  "requests": [
    {
      "principal": "User::\"alice\"",
      "action": "view",
      "resource": {
        "type": "Photo",
        "id": "photo1.jpg"
      }
    },
    {
      "principal": "User::\"bob\"",
      "action": "edit",
      "resource": {
        "type": "Photo",
        "id": "photo2.jpg"
      }
    }
  ]
}
```

**Response:**

```json
{
  "results": [
    {
      "index": 0,
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
      "status": "error",
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

### POST /api/v1/batch_check_detailed - Detailed Results

Process multiple authorization requests and return detailed results (includes policy information).

**Request:**
Same as `/batch_check`

**Response:**

```json
{
  "results": [
    {
      "index": 0,
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
      "status": "error",
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

### Result Structure

#### Success Result

```json
{
  "index": 0,
  "status": "success",
  "result": { /* CheckResponse data */ }
}
```

#### Error Result

```json
{
  "index": 1,
  "status": "error",
  "error": "Error message string"
}
```

### Usage Examples

#### curl Example

```bash
curl -X POST http://localhost:9999/api/v1/batch_check \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "principal": "User::\"alice\"",
        "action": "view",
        "resource": {
          "type": "Photo",
          "id": "vacation.jpg"
        }
      },
      {
        "principal": "User::\"alice\"",
        "action": "delete",
        "resource": {
          "type": "Photo",
          "id": "vacation.jpg"
        }
      }
    ]
  }'
```

#### Python Example

```python
import requests

response = requests.post(
    "http://localhost:9999/api/v1/batch_check",
    json={
        "requests": [
            {
                "principal": 'User::"alice"',
                "action": "view",
                "resource": {
                    "type": "Photo",
                    "id": "vacation.jpg"
                }
            },
            {
                "principal": 'User::"bob"',
                "action": "edit",
                "resource": {
                    "type": "Photo",
                    "id": "vacation.jpg"
                }
            }
        ]
    }
)

data = response.json()
print(f"Successful: {data['successful']}, Failed: {data['failed']}")

for result in data['results']:
    index = result['index']
    if result['status'] == 'success':
        decision = result['result']['decision']
        print(f"Request {index}: {decision}")
    else:
        error = result['error']
        print(f"Request {index}: Error - {error}")
```

#### JavaScript/TypeScript Example

```typescript
const response = await fetch('http://localhost:9999/api/v1/batch_check', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    requests: [
      {
        principal: 'User::"alice"',
        action: 'view',
        resource: {
          type: 'Photo',
          id: 'vacation.jpg'
        }
      },
      {
        principal: 'User::"bob"',
        action: 'edit',
        resource: {
          type: 'Photo',
          id: 'vacation.jpg'
        }
      }
    ]
  })
});

const data = await response.json();
console.log(`Successful: ${data.successful}, Failed: ${data.failed}`);

data.results.forEach(result => {
  if (result.status === 'success') {
    console.log(`Request ${result.index}: ${result.result.decision}`);
  } else {
    console.log(`Request ${result.index}: Error - ${result.error}`);
  }
});
```

### Performance Considerations

1. **Parallel Execution**: Requests are processed in parallel across available CPU cores using Rayon
2. **Lock Management**: The policy store lock is acquired once and released before parallel processing begins
3. **Engine Snapshot**: A snapshot of the PolicyEngine is cloned for consistent evaluation

### Best Practices

1. **Batch Size**: For optimal performance, batch request counts per call depending on your use case and server capacity
2. **Error Handling**: Check both the HTTP status code and individual result statuses
3. **Consistency**: All requests in a batch are guaranteed to be evaluated against the same policy version
4. **Indexing**: Use the `index` field in results to correlate responses with requests

### Comparison with Single Request API

| Feature | Single Request | Batch Request |
| ------- | ------------- | ------------- |
| Requests per call | 1 | Multiple |
| HTTP overhead | Per request | Once per batch |
| Lock acquisition | Per request | Once per batch |
| Policy version | Per request | Consistent across batch |
| Parallel processing | No | Yes (Rayon) |
| Result tracking | Single result | Indexed results with success/error |
