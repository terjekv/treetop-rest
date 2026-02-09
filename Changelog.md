# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
