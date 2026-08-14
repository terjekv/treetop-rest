# Performance characterization

Treetop REST provides a repeatable, opt-in end-to-end characterization alongside deterministic
[Gungraun instruction-count benchmarks](../benches/). The characterization answers two different questions:

- What latency does an HTTP client observe for representative single and batch workloads?
- Where does Treetop Core spend policy-evaluation time inside those requests?

The results are observations, not release gates. Wall-clock latency depends on the CPU, kernel, power management,
contention, policy and label data, payload shape, concurrency, and build profile.

## Timing layers

The three timing layers are deliberately kept separate:

```text
client-observed HTTP round trip
└── server-side HTTP handling       http_request_duration_seconds
    └── one or more evaluations     policy_eval_duration_seconds
        ├── label application       phase="apply_labels"
        ├── Cedar entity building   phase="construct_entities"
        ├── group resolution        phase="resolve_groups"
        ├── Cedar authorization     phase="cedar_authorize"
        └── remaining core work     phase="overhead"
```

The characterization's HTTP timer starts before the client sends a request and stops after the complete response body
has been read over an ephemeral loopback connection. It therefore includes the client library, loopback transport,
server handling, response serialization, and response transfer.

The HTTP histogram starts inside Treetop's tracing middleware and stops when the Actix service returns its response. It
does not include client work or transferring the completed response to the client. The policy histograms come directly
from the `treetop-core` 0.0.20 observability sink:

- `policy_eval_duration_seconds` is Core's total evaluation timer for one authorization decision.
- `cedar_authorize` measures the Cedar `Authorizer::is_authorized` call.
- `overhead` is Core's non-negative residual: total minus the four exported named phases. It currently includes Cedar
  request construction, decision/diagnostic materialization, other unpartitioned Core work, and timer precision.

A batch has one HTTP observation and one policy/phase observation per decision. Batches may run decisions concurrently,
so HTTP time is neither the sum of evaluation times nor directly comparable to a single evaluation percentile.
Percentiles from separate histograms must not be added or subtracted.

## Deterministic regression benchmarks

The pull-request performance workflow discovers every `benches/*_callgrind.rs` target and compares its instruction
count with the base commit. Unlike the wall-clock characterization, these Gungraun/Callgrind results are deterministic
enough to enforce the workflow's regression threshold.

Authorization is covered in both configurations that matter for interpreting observability cost:

- `authorize_batch_brief_128_callgrind` evaluates 128 decisions with Treetop Core's no-op metrics sink.
- `authorize_batch_metrics_128_callgrind` runs the same workload after installing the production Prometheus sink. Its
  setup is outside the measured region, while metric recording for every decision remains inside it.

Run an individual comparison locally with the Gungraun runner matching the repository dependency:

```bash
cargo install gungraun-runner --version 0.19.4 --locked
cargo bench --bench authorize_batch_brief_128_callgrind
cargo bench --bench authorize_batch_metrics_128_callgrind
```

Gungraun compares against the prior local result for the same target. Run it once before and once after a change without
removing `target/gungraun` between runs. Compare absolute instruction counts between the no-op and production-metrics
targets only when both were built from the same commit with the same toolchain.

## Reproduce the characterization

Run the ignored test in release mode. It starts a real Actix server on an ephemeral loopback port and does not need
Docker, a fixed port, or an external service:

```bash
cargo test --release --test latency_characterization -- --ignored --nocapture
```

The defaults are 500 warm-up requests followed by 5,000 measured requests per workload at concurrency 1 and
`min(logical CPUs, 8)`. Override them with:

| Variable | Default | Meaning |
| --- | ---: | --- |
| `TREETOP_PERF_SAMPLES` | `5000` | Measured HTTP requests per workload and concurrency. |
| `TREETOP_PERF_WARMUP` | `500` | Unmeasured warm-up requests per workload and concurrency. |
| `TREETOP_PERF_CONCURRENCIES` | `1,min(CPUs,8)` | Comma-separated in-flight request counts. |
| `TREETOP_PERF_OUTPUT` | unset | Write a reviewable, machine-anonymous JSON report to this path. |
| `TREETOP_PERF_WORKERS` | production default | Override the Actix worker count for a controlled experiment. |
| `TREETOP_PERF_RAYON_THREADS` | production default | Override the Rayon thread count for a controlled experiment. |
| `TREETOP_PERF_PAR_THRESHOLD` | `8` | Override the minimum batch size that can use Rayon. |

For example:

```bash
TREETOP_PERF_SAMPLES=10000 \
TREETOP_PERF_WARMUP=1000 \
TREETOP_PERF_CONCURRENCIES=1,8,32 \
TREETOP_PERF_OUTPUT=treetop-performance.json \
cargo test --release --test latency_characterization -- --ignored --nocapture
```

Keep the machine otherwise idle, use a fixed CPU governor when possible, and repeat the run before drawing conclusions
from tail percentiles. The harness intentionally installs no tracing subscriber, so request logging does not distort
the measured server path. Production metrics remain active.

## Compare CPU allocations and runtime layouts

On Linux, the matrix runner defaults to directly comparable 1-, 2-, 4-, and 8-CPU samples. It uses `taskset` to limit
the whole benchmark process to real CPUs from its current affinity, builds the release test once, then writes one
anonymous JSON report per run plus a combined HTTP summary. The defaults are only a starting point; both the counts and
exact CPU IDs are selectable.

```bash
scripts/run-performance-matrix.sh
```

The default output is ignored by Git in `performance-results/`:

```text
performance-results/
├── 1cpu-default.json
├── 2cpu-default.json
├── 4cpu-default.json
├── 8cpu-default.json
└── summary.md
```

Select arbitrary allocation sizes, sample count, and output directory with environment variables. Count-based runs use
the first allowed CPUs from the runner's current affinity. Counts larger than that affinity are reported and skipped:

```bash
TREETOP_PERF_CPU_COUNTS=1,2,4 \
TREETOP_PERF_SAMPLES=10000 \
TREETOP_PERF_WARMUP=1000 \
TREETOP_PERF_OUTPUT_DIR=performance-results/my-machine \
scripts/run-performance-matrix.sh
```

On SMT, NUMA, or heterogeneous-core systems, choose the exact CPU topology with semicolon-separated CPU sets. Commas
and inclusive ranges have the same syntax as `taskset`; setting `TREETOP_PERF_CPU_SETS` overrides
`TREETOP_PERF_CPU_COUNTS`:

```bash
TREETOP_PERF_CPU_SETS='0;0,2;0,2,4,6;8-11' \
scripts/run-performance-matrix.sh
```

Every selected CPU must be inside the runner's current affinity, and a CPU cannot appear twice in one set. Exact-set
reports use names such as `cpus-0_2_4_6-default.json`. Both the JSON and combined Markdown table record the effective
affinity, not only its CPU count.

The `default` layout measures the production worker and batch-parallelism calculation for each allocation. To explain
where scaling comes from, compare it with controlled thread-layout experiments:

| Layout | Actix workers | Rayon threads | Question answered |
| --- | ---: | ---: | --- |
| `default` | production calculation | production calculation | How does the server scale without overrides? |
| `http` | allocated CPUs | 1 | How do independent HTTP requests scale? |
| `batch` | 1 | allocated CPUs | How does one large authorization batch scale? |
| `full` | allocated CPUs | allocated CPUs | What happens when both pools can use the allocation? |

Run all four layouts with:

```bash
TREETOP_PERF_CPU_COUNTS=1,2,4 \
TREETOP_PERF_LAYOUTS=default,http,batch,full \
scripts/run-performance-matrix.sh
```

`full` can create more runnable threads than allocated CPUs when HTTP and batch work overlap. It is a saturation
experiment, not a deployment recommendation. Compare the highest tested concurrency for request throughput and
single-request latency, and compare `authorize_batch_128` at concurrency 1 for within-batch scaling. A larger CPU
allocation does not guarantee improvement: flat or worse results can reveal a serial workload, a production threshold,
queueing, or thread-pool overhead. Publish those results rather than selecting only improving rows.

The generated JSON records the observed CPU allocation and exact affinity, actual Actix/Rayon settings, threshold, CPU
model, operating system, kernel, governor, Rust target, and exact REST/Core versions and source SHAs. This keeps the
matrix reproducible and makes differently configured rows auditable.

## Sustained and remote load with k6

Use the Rust characterization for a self-contained, fixed-fixture comparison and Core phase attribution. Use k6 when
the question is sustained load, a controlled request arrival rate, or client-observed performance from another node.
The included scenario is dependency-free and verified with k6 2.2.0:

```bash
TREETOP_K6_BASE_URL=http://127.0.0.1:9999 \
TREETOP_K6_WORKLOAD=authorize_labeled \
TREETOP_K6_MODE=duration \
TREETOP_K6_VUS=8 \
TREETOP_K6_DURATION=60s \
TREETOP_K6_OUTPUT=performance-results/k6-8vu.json \
scripts/run-k6.sh
```

The wrapper passes `--no-usage-report`, so running it does not send k6's anonymous usage statistics. It writes a local
machine-anonymous JSON summary and a compact console summary. It does not send benchmark results anywhere.

The k6 bodies match `testdata/default.cedar` and `testdata/labels.json`; point the test at a server loaded with those
fixtures when comparing runs. A `2xx` response is required for every iteration. Available workloads are `livez`,
`policies`, `authorize_simple`, `authorize_labeled`, `authorize_batch_8`, `authorize_batch_128`, and `mixed`.

One way to start that server locally is to run the repository's testdata host in one terminal, then REST in another:

```bash
docker compose up
```

```bash
TREETOP_POLICY_URL=http://127.0.0.1:8080/default.cedar \
TREETOP_LABELS_URL=http://127.0.0.1:8080/labels.json \
cargo run --release --bin treetop-server
```

Wait for `curl --fail http://127.0.0.1:9999/readyz` before starting k6. Stop the testdata host with
`docker compose down` after the run.

| Mode | Main controls | Use |
| --- | --- | --- |
| `iterations` | `TREETOP_K6_ITERATIONS`, `TREETOP_K6_VUS`, `TREETOP_K6_MAX_DURATION` | A fixed sample count. |
| `duration` | `TREETOP_K6_VUS`, `TREETOP_K6_DURATION` | Maximum throughput under a fixed client concurrency. |
| `rate` | `TREETOP_K6_RATE`, `TREETOP_K6_VUS`, `TREETOP_K6_MAX_VUS`, `TREETOP_K6_DURATION` | Latency at a fixed arrival rate and overload detection through dropped iterations. |

For a publishable result, provide the target build provenance and the server CPU allocation. These values are copied
into the report and do not become metric tags:

```bash
TREETOP_K6_REST_VERSION=0.0.11 \
TREETOP_K6_REST_SHA=<full-rest-sha> \
TREETOP_K6_CORE_VERSION=0.0.19 \
TREETOP_K6_CORE_SHA=<full-core-sha> \
TREETOP_K6_CEDAR_VERSION=4.12.0 \
TREETOP_K6_SERVER_CPUS=0-3 \
TREETOP_K6_CLIENT_CPUS=31 \
scripts/run-k6.sh
```

On a single node, reserve non-overlapping CPUs for the server and load generator. For example, pin 1-, 2-, and 4-CPU
server runs to CPU lists `0`, `0,1`, and `0,1,2,3`, while setting `TREETOP_K6_CLIENT_CPUS` to another available CPU or
set. The wrapper uses `taskset` for that client allocation and records both the declared server set and effective client
set. Keep the k6 VU/rate settings identical across those runs. If the machine cannot reserve separate load-generator
capacity, use the Rust matrix and describe its client-plus-server CPU allocation honestly. For the cleanest
server-capacity measurement, run k6 from a separate, otherwise idle node and record that load-generator setup alongside
the anonymous server report.

k6 reports the full client HTTP request time. Scrape `/metrics` during the same interval for the server-side HTTP,
Treetop Core total, and Core phase distributions; those layers retain the semantics described above. Do not add or
subtract their independently aggregated percentiles.

## Workloads

| Workload | Request | Purpose |
| --- | --- | --- |
| `livez` | `GET /livez` | Minimal operational HTTP baseline. |
| `policies` | `GET /api/v1/policies` | Policy retrieval and JSON serialization. |
| `authorize_simple` | One simple decision | Core evaluation without label-dependent policy matching. |
| `authorize_labeled` | One labeled host decision | Label application, entity construction, groups, and Cedar. |
| `authorize_batch_8` | Eight labeled decisions | Small batch below or near practical parallel thresholds. |
| `authorize_batch_128` | 128 labeled decisions | Large batch using the production Rayon boundary. |

The inline policy and label fixtures are fixed in `tests/latency_characterization.rs`, making repeated runs comparable.
They are representative probes, not substitutes for benchmarking a deployment's own policies and request shapes.

## Example result

This example was collected on 2026-08-13 from the PR working tree based on
`78daa6659785e06a4a12c88d806aa5c40461fb0b`. It used Rust 1.97.1, release mode, Linux
5.14.0-687.33.1.el9_8.x86_64, the `performance` governor, and an Intel Xeon Silver 4216 at 2.10 GHz with 32 logical
CPUs. Treetop REST was 0.0.11, Treetop Core was 0.0.19, and Cedar was 4.12.0. Each row used 200 warm-ups and 2,000
samples. These numbers illustrate the output and the sub-millisecond resolution needed; they are not service-level
objectives or capacity promises. The packaged Treetop Core source SHA was
`9d7589ece08d318f2fa5e25090c1629cb1da81b3`.

| Workload | Concurrency | Requests/s | Mean µs | p50 µs | p95 µs | p99 µs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `livez` | 1 | 17,826 | 55.8 | 55.6 | 58.6 | 60.7 |
| `policies` | 1 | 16,621 | 59.9 | 59.6 | 62.6 | 65.1 |
| `authorize_simple` | 1 | 9,838 | 101.3 | 100.5 | 106.0 | 118.9 |
| `authorize_labeled` | 1 | 9,011 | 110.7 | 110.1 | 115.8 | 117.6 |
| `authorize_batch_8` | 1 | 3,478 | 287.2 | 286.2 | 293.0 | 304.9 |
| `authorize_batch_128` | 1 | 497 | 2,010.2 | 2,007.1 | 2,046.2 | 2,079.3 |
| `livez` | 8 | 38,532 | 196.6 | 194.9 | 211.6 | 217.4 |
| `policies` | 8 | 38,164 | 196.9 | 196.0 | 213.2 | 216.4 |
| `authorize_simple` | 8 | 37,493 | 193.9 | 195.4 | 216.8 | 226.6 |
| `authorize_labeled` | 8 | 37,378 | 193.4 | 195.2 | 216.7 | 224.6 |
| `authorize_batch_8` | 8 | 24,611 | 323.9 | 321.7 | 340.6 | 367.0 |
| `authorize_batch_128` | 8 | 2,645 | 3,018.1 | 2,755.8 | 4,546.1 | 5,628.4 |

The phase table aggregates all warm-up and measured decisions at both concurrency levels. Values are means per decision:

| Workload | Evaluations | Total µs | Labels µs | Entities µs | Groups µs | Cedar µs | Overhead µs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `authorize_simple` | 4,400 | 19.9 | 0.3 | 4.7 | 0.2 | 11.2 | 3.5 |
| `authorize_labeled` | 4,400 | 25.6 | 1.9 | 7.8 | 0.2 | 11.8 | 4.0 |
| `authorize_batch_8` | 35,200 | 18.5 | 1.2 | 5.4 | 0.1 | 9.2 | 2.5 |
| `authorize_batch_128` | 563,200 | 20.4 | 1.4 | 5.5 | 0.1 | 10.8 | 2.6 |

### Example CPU scaling result

The same node was constrained to CPU sets `0`, `0,16`, `0,1`, `0-3`, and `0-7` with the matrix runner's `default`
production layout. CPUs 0 and 16 are SMT siblings on one physical core; CPUs 0 and 1 are separate physical cores. Each
point used 200 warm-ups and 1,000 samples. The run used clean REST commit
`b82bc76b0074b53081cb6231aa8a6c63bff72073` and the Core SHA above. This sample is sufficient to illustrate the report
and topology effects, but should be repeated with the default or a larger sample count before using its tail values for
capacity planning. The [published result](performance-results/2026-08-13-xeon-silver-4216.md) contains the complete
HTTP table, phase means, CPU specifications, and reproduction command.

| CPU set | Actix/Rayon | Maximum concurrency | `livez` requests/s | Simple authorize requests/s | Batch-128 requests/s at concurrency 1 | Batch-128 p95 at concurrency 1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `0` | 1/1 | 1 | 15,910 | 5,758 | 140 | 7,182.0 µs |
| `0,16` | 1/1 | 2 | 19,339 | 7,395 | 138 | 7,274.8 µs |
| `0,1` | 1/1 | 2 | 30,365 | 10,096 | 141 | 7,161.6 µs |
| `0-3` | 2/2 | 4 | 34,561 | 17,974 | 249 | 4,054.1 µs |
| `0-7` | 4/4 | 8 | 38,434 | 34,782 | 420 | 2,401.9 µs |

Two logical CPUs are not necessarily two cores: at concurrency 2, the SMT-sibling set reached about 73% of the simple
authorization throughput of the separate-core set. The cheap liveness path approached a plateau after two physical
cores, while independent simple authorization throughput continued to scale through eight CPUs. A single 128-decision
batch remained flat while the production calculation selected one Rayon thread, then improved when two and four Rayon
threads became available. This is an observed mechanism, not an assumption that every workload scales linearly. The
report's exact affinity and parallel configuration make that distinction visible.

## Share an anonymous result

Setting `TREETOP_PERF_OUTPUT` writes a self-contained JSON report with:

- CPU model, logical core count and exact affinity, OS/kernel/architecture, CPU governor, Rust version, and compilation
  target/profile;
- Treetop REST, Treetop Core, and Cedar versions, plus REST/Core source SHAs and dirty-worktree state when build
  metadata provides them;
- Actix worker, Rayon thread, batch-threshold, warm-up, sample, and concurrency settings;
- HTTP summaries, phase means, and raw request durations.

The report does not collect hostname, username, IP addresses, filesystem paths, Git branch, policy contents, labels, or
request bodies. Source SHAs are included because they identify code, not the machine. Result publication is never
automatic: inspect the JSON, then attach it to a GitHub issue or pull request if you choose to share it. A GitHub
submission is associated with the submitting GitHub account even though the benchmark payload is machine-anonymous.

Do not publish a report if local policy requires additional review. In particular, an exact kernel build or CPU model
may still be considered infrastructure information in some environments.

## Comparing runs

- Compare like-for-like workloads, versions, build profiles, concurrency, and parallel configuration.
- Use HTTP latency and throughput for client-facing capacity questions.
- Use total and phase means to decide where optimization work belongs.
- Use p95/p99 only with enough samples and repeated runs; a 5,000-sample p99 is based on roughly 50 tail observations.
- Treat changes smaller than normal run-to-run variance as inconclusive. Use the deterministic Gungraun benchmarks to
  confirm instruction-level regressions before attributing a wall-clock change to code.
- Inspect saturation across concurrency levels. Lower per-decision Core time does not guarantee lower batch HTTP latency
  when scheduling, serialization, and queueing dominate.

Metric exposition, PromQL examples, bucket layout, and migration guidance are documented in
[the metrics API reference](api.md#get-metrics).
