# Fuzz testing

The fuzz suite exercises security-sensitive, attacker-controlled input boundaries without requiring Docker or external
services:

- `authorize_json` deserializes authorization request JSON, evaluates accepted batches, and checks response cardinality,
  ordering, identifiers, and agreement between brief and detailed decisions.
- `state_updates` mutates policy, schema, and label inputs and verifies that rejected updates leave the last-known-good
  engine and metadata unchanged.

The targets use [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) and require a nightly Rust toolchain.

```bash
cargo install cargo-fuzz --locked
cargo +nightly fuzz run authorize_json -- -max_len=65536
cargo +nightly fuzz run state_updates -- -max_len=65536
```

Keep minimized reproductions as regression tests when they expose a defect. The checked-in corpus contains valid seeds
that take each target beyond its initial parser checks.
