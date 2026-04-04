use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use treetop_rest::cli::matrix::expand_matrix;

#[library_benchmark]
fn matrix_simple() {
    let _ = expand_matrix("alice|bob", "Read", "Document", "doc1", vec![]);
}

library_benchmark_group!(name = cli_matrix_simple; benchmarks = matrix_simple);

main!(library_benchmark_groups = cli_matrix_simple);
