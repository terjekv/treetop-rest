# Test Suite for Treetop REST

This project includes a comprehensive test suite covering unit tests, integration tests,
and CLI parsing tests. The tests are designed to run without Docker, making them fast and
easy to execute during development.

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

### Integration Tests (in `tests/`)

Integration tests are in separate files in the `tests/` directory.

#### Handler Tests (`tests/handler_tests.rs`)

Tests for HTTP API endpoints using Actix-web test utilities:

- **Health endpoint** - Service health check
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

#### CLI Parsing Tests (`tests/cli_parsing_tests.rs`)

Tests for command-line argument parsing logic using **parameterized tests**:

- **IP parsing**: IPv4 and IPv6 addresses (4 cases)
- **Long/integer parsing**: positive, negative, zero, large numbers (4 cases)
- **Boolean parsing**: true/false (2 cases)
- **Key-value parsing**: simple, with equals in value, URLs (4 cases)
- **Quoted string handling**: quoted, unquoted strings (4 cases)
- **Whitespace handling**: various spacing patterns (3 cases)
- **Error cases**: empty keys (3 cases), missing equals (3 cases)
- Single test for multiple attributes
- Single test for AttrValue conversions

## Running Tests

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
cargo test --test cli_parsing_tests
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

## Test Coverage

The current test suite includes **80 test cases** covering:

- ✅ **Models** (4 tests): Endpoint parsing, decision conversions
- ✅ **State** (14 tests): Metadata handling, policy store management, label processing
- ✅ **Handlers** (14 tests): All HTTP endpoints with parameterized token validation
- ✅ **CLI** (29 tests): Parameterized parsing tests for all input types
- ✅ **Integration** (19 tests): Parameterized authorization scenarios with real policies

### Parameterized Test Benefits

Using `rstest`, we've consolidated repetitive tests:

- **Before**: 6+ separate authorization tests → **After**: 1 parameterized test with 6 cases
- **Before**: 5+ IP range tests → **After**: 1 parameterized test with 5 cases
- **Before**: Multiple parsing tests → **After**: Consolidated with multiple cases each
- **Result**: More test cases, less code duplication, easier to add new scenarios

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

## Performance

The test suite is fast despite having **80 test cases**:

- Unit tests (18): < 0.02 seconds
- CLI tests (29): < 0.01 seconds
- Handler tests (14): < 0.02 seconds
- Integration tests (19): < 0.04 seconds
- **Total test execution**: < 0.1 seconds

This makes them ideal for:

- Pre-commit hooks
- Watch mode during development (`cargo watch -x test`)
- Rapid feedback loops
- CI/CD pipelines

The parameterized tests run efficiently as each case is executed independently.

## Dependencies

Test-specific dependencies (in `[dev-dependencies]`):

- `actix-rt` - Async runtime for Actix tests
- `rstest` - Parameterized testing framework
- `tempfile` - Temporary file creation (currently unused, available for future tests)

## Future Improvements

Potential additions to the test suite:

- [ ] Property-based testing with `proptest`
- [ ] Benchmark tests with `criterion`
- [ ] More edge cases for label regex patterns
- [ ] Negative test cases for malformed requests
- [ ] Performance tests for large policy sets
- [ ] CLI REPL interaction tests
- [ ] Concurrency tests for shared state
