# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added a canonical generated OpenAPI document at `/openapi.json`, a checked-in
  `docs/openapi.json` copy with stale-document checks, and documented regeneration.

### Changed

- Configured Swagger UI to load `/openapi.json` while preserving
  `/api-docs/openapi.json` as a compatibility alias.
- Documented operation tags, upload-token security, supported JSON and plain-text
  representations, and the actual structured error response in the generated spec.

### Fixed

- Made the generated schema-upload alternatives valid for standard OpenAPI
  validators while preserving the public Rust `handlers::ApiDoc` entry point.

## [0.0.9] - 2026-08-12

### Fixed

- Isolated each Linux release target's cross-compilation artifacts so host build scripts are not reused across
  incompatible container glibc versions.

## [0.0.8] - 2026-08-12

### Added

- Added continuous fuzz testing for authorization request handling and atomic policy, schema, and label reloads.
- Added `/livez` and `/readyz` operational probes, including readiness tracking for the initial successful load of
  every configured remote policy, label, and schema source.

### Changed

- Updated `treetop-core` to version `0.0.19`.
- Migrated performance benchmarks from `iai-callgrind` to Gungraun 0.19.4 and upgraded the reusable benchmark
  workflow from v1 to v3.
- Updated the Cargo dependency graph to current Rust 1.97-compatible releases, including Actix Web 4.14.1 and Cedar
  Policy 4.12.0.
- Upgraded GitHub Actions dependencies, pinned the release and cross-compilation tools, and added Dependabot coverage
  for GitHub Actions and container images.
- Updated the build and runtime containers to Rust 1.97, Alpine 3.24, and miniserve 0.35.0.
- Disabled crates.io publishing for the server package; supported release artifacts remain container images and
  prebuilt binaries.

### Security

- Added a configurable authorization batch limit to bound evaluation work per request.
- Authenticate policy and schema uploads before parsing their bodies, while retaining a second authorization check
  before applying an update.

## [0.0.7] - 2026-07-04

### Changed

- Updated direct dependencies to current compatible releases, including `lru` 0.18, `tabled` 0.21, and the
  `vergen` 10 build metadata toolchain.
- Updated `treetop-core` to version `0.0.18`.
- Refreshed the full Cargo lockfile to the latest Rust 1.96-compatible dependency graph.

### Fixed

- Migrated the build script to the `vergen` 10 API so release build metadata continues to include Cargo, Rust, build,
  and Git information.

## [0.0.6] - 2026-04-04

### Added

- Request context evaluation support on `POST /api/v1/authorize`.
- Runtime context status on `GET /api/v1/status` via `request_context.{supported,schema_backed,fallback_reason}`.

### Changed

- Updated `treetop-core` to version `0.0.17`.
- Updated direct Cedar dependencies to the `4.9` line used by the new core release.
- Uploaded schemas now participate in live runtime evaluation when compatible with the active policies.
- In permissive schema mode, incompatible schema uploads are retained as metadata while evaluation falls back to a
  schema-free engine.
- CLI `status` output now shows whether request-context evaluation is schema-backed or running in fallback mode.

### Fixed

- Evaluate authorize requests with supplied `context` instead of validating and then ignoring it.
- Preserve schema-backed runtime behavior when labels are reloaded.
- Map `treetop-core` request, context, and evaluation errors to the correct REST error categories.
- Refresh API and README documentation for context support, `/status`, and current release behavior.

## [0.0.5] - 2026-04-04

### Added

- Cedar schema management support, including `GET /api/v1/schema` and `POST /api/v1/schema`.
- CLI support for downloading and uploading schemas, including `upload --schema`.
- Schema validation and schema-fetch configuration for policy/schema reloads.
- Match reasons in user policy responses via `matches[].reasons`.
- Configurable request body size limit via `TREETOP_MAX_REQUEST_SIZE`.

### Changed

- Improved shared policy store concurrency and robustness under poisoned-lock scenarios.
- Split and renamed benchmark targets with `_callgrind` suffix for better perf workflow discovery.
- Updated API and configuration documentation to cover schema support and current server behavior.

### Fixed

- Send `X-Upload-Token` correctly on JSON upload paths.
- Correct Docker healthcheck path to `/api/v1/health`.
- Ensure generic fetcher updates hashes and metadata correctly to avoid unnecessary reloads.
- Correct OpenAPI annotations for GET endpoints such as health and version.
- Refresh README and API examples to use current endpoint paths and upload behavior.

## [0.0.4] - 2026-02-09

### Added

- Group membership support for policy retrieval via `groups` query parameter on `/api/v1/policies/{user}` endpoint
- Test suite for group membership filtering functionality
- Performance tracking via `iai-callgrind` action
- Dependabot support

### Changed

- Updated `treetop-core` to version 0.0.16.
- **CLI**: Consolidated `get-policies` and `list-policies` commands into single `policies` command
- **CLI**: Added `--user` flag to `policies` command for retrieving user-specific policies
- **CLI**: Added support for group membership syntax using bracket notation (e.g., `DNS::User::alice[admins,developers]`)

### Fixed

- **CLI**: Extract entity ID from namespaced principals (e.g., `DNS::User::alice` → `alice`) before making API requests,
as the API expects just the entity ID

## [0.0.3] - 2026-02-01

### Changed

- Updates `treetop-core` to version 0.0.14.
- **BREAKING** Brief authorization responses now include the policy identifier in the `policy_id` field

## [0.0.2] - 2026-01-31

### Changed

- Migrate to single authorize endpoint, `/api/v1/authorize`, which handles both single and batch requests.
- Update CLI to use the new unified authorize endpoint for all permission checks.
- Remove all other authorize endpoints.
- Remove principal from metrics labels to reduce cardinality.
