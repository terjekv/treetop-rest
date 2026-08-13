# Test Suite for Treetop REST

This project includes a comprehensive test suite covering server unit and integration tests. The
tests are designed to run without Docker, making them fast and easy to execute during development.

**The test suite uses `rstest` for parameterized testing**, which allows us to write more
concise tests that cover multiple scenarios with different inputs. This approach significantly
reduces code duplication while expanding test coverage.

## Test Structure

### Unit Tests (in `src/`)

Unit tests are colocated with the source code using Rust's built-in `#[cfg(test)]` module convention.

#### Models Tests (`src/models.rs`)

- **Endpoint** parsing and validation
  - URL parsing from strings
  - Invalid URL handling
  - Display formatting

#### State Tests (`src/state.rs`)

- **Metadata** creation and validation
  - Empty metadata handling
  - Policy counting from Cedar DSL
  - Label JSON parsing and validation
  - SHA256 hash generation
  - Source and refresh frequency preservation
- **PolicyStore** functionality
  - Initialization with default/empty state
  - DSL policy loading and validation
  - Label loading with regex pattern validation
  - Invalid input handling (malformed DSL, invalid JSON, bad regex patterns)
  - Metadata preservation across updates

#### Server Tests (`src/bin/server.rs`)

- **Swagger UI configuration**: The production server factory loads the canonical
  `/openapi.json` document

### Integration Tests (in `tests/`)

Integration tests are in separate files in the `tests/` directory.

#### Handler Tests (`tests/handler_tests.rs`)

Tests for HTTP API endpoints using Actix-web test utilities:

- **Health endpoint** - Service health check
- **OpenAPI endpoints** - Canonical and compatibility documents
- **Status endpoint** - Service status and metadata
- **Check endpoint** - Authorization evaluation
  - Allow decisions
  - Deny decisions (forbid policies)
  - Resource attributes (IP ranges)
  - Out-of-range denials
- **Get policies** - Policy retrieval
  - JSON format
  - Raw text format
- **Upload policies** - **Parameterized token validation** (4 cases):
  - Matching tokens (success)
  - Mismatched tokens (failure)
  - Multiple token scenarios
  - Upload not allowed (separate test)
- **List policies** - User-specific policy listing

#### Integration Tests (`tests/integration_tests.rs`)

End-to-end tests using the actual test data files (`testdata/`):

- Loading test policies and labels
- **Parameterized authorization tests** covering:
  - Alice: view (allow), edit (deny), delete (deny), only_here (allow)
  - Bob: delete (deny), only_here (deny)
  - Multiple test cases in a single test function
- **Parameterized IP range tests** covering:
  - Multiple IPs in valid range (10.0.0.0/24): Allow
  - Multiple IPs outside range: Deny
  - Edge cases and boundary conditions
- Label JSON structure validation
- Policy counting and versioning
- SHA256 hash validation
- Content size tracking

#### Client Allowlist Tests (`tests/client_allowlist_tests.rs`)

Tests for IP/CIDR whitelist and proxy header trust configuration:

- **IPv4 whitelisting**: Allowing requests from whitelisted CIDR ranges
- **IPv4 rejection**: Rejecting requests from non-whitelisted addresses
- **IPv6 support**: Allowing whitelisted IPv6 addresses
- **Trust header toggle**: Ignoring spoofed proxy headers when trust is disabled

#### Metrics Tests (`tests/metrics_tests.rs`)

Tests for Prometheus metrics collection and reporting:

- **Metrics endpoint**: Availability and content-type validation
- **Build info**: Version labels (app, core, Cedar)
- **Policy evaluation metrics**: Counters for evaluations, allowed/denied decisions
- **HTTP request metrics**: Route-template request counting and duration histograms
- **Client IP tracking**: Proxy-header-aware IP labels in HTTP metrics
- **Histogram validation**: Exact sub-millisecond classic boundaries plus native protobuf buckets
- **Core phase metrics**: Labels, entity construction, group resolution, Cedar, and residual overhead
- **Exposition formats**: OpenMetrics text and negotiated Prometheus protobuf

#### Latency Characterization (`tests/latency_characterization.rs`)

An ignored, threshold-free end-to-end characterization starts an in-process Actix server on an ephemeral loopback port.
It reports full client HTTP timing and the corresponding Treetop Core phase means for health, policy retrieval, simple,
labeled, and batch authorization workloads. It also supports an explicitly requested machine-anonymous JSON export.

Run it in release mode:

```bash
cargo test --release --test latency_characterization -- --ignored --nocapture
```

On Linux, generate the default 1-, 2-, 4-, and 8-CPU JSON samples and a combined Markdown scaling table with:

```bash
scripts/run-performance-matrix.sh
```

See [`docs/performance.md`](../docs/performance.md#compare-cpu-allocations-and-runtime-layouts) for arbitrary CPU counts,
exact CPU sets, sample/concurrency controls, and Actix/Rayon layouts.

For sustained, fixed-arrival-rate, or remote load against an already running server, use the k6 2.2.0-compatible
scenario:

```bash
TREETOP_K6_MODE=duration TREETOP_K6_VUS=8 TREETOP_K6_DURATION=60s scripts/run-k6.sh
```

The wrapper disables k6 usage reporting. Workloads, source-provenance fields, result privacy, and single-node CPU
isolation are documented in [`docs/performance.md`](../docs/performance.md#sustained-and-remote-load-with-k6).

See [`docs/performance.md`](../docs/performance.md) for workload definitions, environment controls, interpretation, and
result-sharing privacy boundaries. The test remains ignored during ordinary `cargo test` because wall-clock output is
machine-dependent; it has no latency pass/fail threshold.

#### OpenAPI Documentation Tests (`tests/openapi_docs_tests.rs`)

- **Generated document parity**: The checked-in OpenAPI JSON must match Utoipa output
- **Regeneration guidance**: Failures identify the command used to refresh the document

#### Detailed Response Tests (`tests/detailed_response_tests.rs`)

- **Typed response contract**: Full authorization responses deserialize through the server-owned
  detailed response model and retain client-provided request identifiers.

## Running Tests

### Fuzz Tests

Security-sensitive input parsing and state transitions have coverage-guided targets under `fuzz/`. See
[`fuzz/README.md`](../fuzz/README.md) for setup and execution instructions. Pull requests run short smoke campaigns,
and the scheduled fuzz workflow runs longer campaigns.

### Run All Tests

```bash
cargo test
```

### Run Only Unit Tests (in src/)

```bash
cargo test --lib
```

### Run Only Integration Tests (in tests/)

```bash
cargo test --tests
```

### Run Specific Test File

```bash
cargo test --test handler_tests
cargo test --test integration_tests
cargo test --test client_allowlist_tests
cargo test --test metrics_tests
cargo test --test latency_characterization
cargo test --test openapi_docs_tests
cargo test --test detailed_response_tests
```

### Run Specific Test by Name

```bash
cargo test test_alice_can_view_photo
cargo test test_endpoint_from_str
```

### Run Tests with Output

```bash
cargo test -- --nocapture
```

### Run Tests in Parallel (default) or Sequential

```bash
cargo test              # parallel (default)
cargo test -- --test-threads=1  # sequential
```

## Test Data

The integration tests use real Cedar policy files and label definitions from `testdata/`:

- `testdata/default.cedar` - Sample Cedar policies with permit and forbid rules
- `testdata/labels.json` - Label definitions with regex patterns for host naming

## Adding New Tests

### Adding Unit Tests

Add tests directly in the relevant source file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_feature() {
        // Test code here
    }
}
```

### Adding Parameterized Tests

Use `rstest` to test multiple cases efficiently:

```rust
use rstest::rstest;

#[rstest]
#[case(input1, expected1)]
#[case(input2, expected2)]
#[case(input3, expected3)]
fn test_with_multiple_cases(#[case] input: Type, #[case] expected: Type) {
    // Test logic that applies to all cases
    assert_eq!(process(input), expected);
}
```

### Adding Integration Tests

Create a new test in `tests/` or add to existing files:

```rust
#[actix_web::test]  // For async Actix tests
async fn test_new_endpoint() {
    // Test code here
}

#[test]  // For synchronous tests
fn test_new_logic() {
    // Test code here
}
```

## CI/CD Integration

These tests are designed to run in CI/CD pipelines without requiring Docker or external services:

```bash
# In your CI pipeline
cargo test --all
```
