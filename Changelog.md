# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.2] - 2026-01-31

### Changed

- Migrate to single authorize endpoint, `/api/v1/authorize`, which handles both single and batch requests.
- Update CLI to use the new unified authorize endpoint for all permission checks.
- Remove all other authorize endpoints.
- Remove principal from metrics labels to reduce cardinality.
