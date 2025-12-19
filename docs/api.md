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
