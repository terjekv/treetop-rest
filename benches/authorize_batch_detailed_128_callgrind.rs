mod authorize_batch;

use authorize_batch::common::bench_detailed;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};

#[library_benchmark]
fn authorize_detailed_128() {
    bench_detailed(128);
}

library_benchmark_group!(
    name = authorize_batch_detailed_128;
    benchmarks = authorize_detailed_128
);

main!(library_benchmark_groups = authorize_batch_detailed_128);
