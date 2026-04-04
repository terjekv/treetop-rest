mod authorize_batch;

use authorize_batch::common::bench_detailed;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};

#[library_benchmark]
fn authorize_detailed_8() {
    bench_detailed(8);
}

library_benchmark_group!(name = authorize_batch_detailed_8; benchmarks = authorize_detailed_8);

main!(library_benchmark_groups = authorize_batch_detailed_8);
