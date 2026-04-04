use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use treetop_rest::cli::matrix::expand_matrix;

#[library_benchmark]
fn matrix_bracketed() {
    let _ = expand_matrix(
        "User::\"alice[admins|webmasters]\"",
        "Action::\"read|write\"",
        "Document|Photo",
        "doc[1|2|3]",
        vec![],
    );
}

library_benchmark_group!(name = cli_matrix_bracketed; benchmarks = matrix_bracketed);

main!(library_benchmark_groups = cli_matrix_bracketed);
