mod authorize_batch;

use authorize_batch::common::bench_brief;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};

#[library_benchmark]
fn authorize_brief_32() {
    bench_brief(32);
}

library_benchmark_group!(name = authorize_batch_brief_32; benchmarks = authorize_brief_32);

main!(library_benchmark_groups = authorize_batch_brief_32);
