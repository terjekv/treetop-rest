use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use treetop_rest::cli::matrix::expand_matrix;

#[library_benchmark]
fn matrix_simple() {
    let _ = expand_matrix("alice|bob", "Read", "Document", "doc1", vec![]);
}

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

#[library_benchmark]
fn matrix_with_attrs() {
    let attrs = vec![
        ("env".to_string(), "prod|stage".to_string()),
        ("region".to_string(), "us-east-1|eu-west-1".to_string()),
    ];
    let _ = expand_matrix("alice|bob", "Read|Write", "Document", "doc[1|2]", attrs);
}

library_benchmark_group!(
    name = cli_matrix;
    benchmarks = matrix_simple, matrix_bracketed, matrix_with_attrs
);

main!(library_benchmark_groups = cli_matrix);
