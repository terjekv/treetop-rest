use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use std::sync::Arc;
use treetop_core::{Action, Principal, Request, Resource, User};
use treetop_rest::handlers::evaluate_batch_requests_for_bench;
use treetop_rest::models::{AuthRequest, AuthorizeDecisionBrief, AuthorizeDecisionDetailed};
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

const DSL: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);

forbid (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"bob",
    action == Action::"create_host",
    resource is Host
)
when { resource.ip.isInRange(ip("10.0.0.0/24")) };
"#;

fn build_engine() -> Arc<treetop_core::PolicyEngine> {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(DSL, None, None).unwrap();
    store.engine.clone()
}

fn build_requests(count: usize) -> Vec<AuthRequest> {
    let principal = Principal::User(User::from_str("alice").unwrap());
    let view_action = Action::from_str("view").unwrap();
    let edit_action = Action::from_str("edit").unwrap();

    (0..count)
        .map(|i| {
            let action = if i % 2 == 0 {
                view_action.clone()
            } else {
                edit_action.clone()
            };
            let request = Request {
                principal: principal.clone(),
                action,
                resource: Resource::new("Photo", "VacationPhoto94.jpg"),
            };
            AuthRequest::new(request)
        })
        .collect()
}

type BenchCtx = (
    Arc<treetop_core::PolicyEngine>,
    ParallelConfig,
    Vec<AuthRequest>,
);

fn setup_brief_8() -> BenchCtx {
    let engine = build_engine();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let requests = build_requests(8);
    (engine, parallel, requests)
}

fn setup_brief_32() -> BenchCtx {
    let engine = build_engine();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let requests = build_requests(32);
    (engine, parallel, requests)
}

fn setup_brief_128() -> BenchCtx {
    let engine = build_engine();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let requests = build_requests(128);
    (engine, parallel, requests)
}

fn setup_detailed_8() -> BenchCtx {
    let engine = build_engine();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let requests = build_requests(8);
    (engine, parallel, requests)
}

fn setup_detailed_32() -> BenchCtx {
    let engine = build_engine();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let requests = build_requests(32);
    (engine, parallel, requests)
}

fn setup_detailed_128() -> BenchCtx {
    let engine = build_engine();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let requests = build_requests(128);
    (engine, parallel, requests)
}

#[library_benchmark(setup = setup_brief_8)]
fn authorize_brief_8((engine, parallel, requests): BenchCtx) {
    let _ = evaluate_batch_requests_for_bench(
        &requests,
        &engine,
        &parallel,
        AuthorizeDecisionBrief::from,
    );
}

#[library_benchmark(setup = setup_brief_32)]
fn authorize_brief_32((engine, parallel, requests): BenchCtx) {
    let _ = evaluate_batch_requests_for_bench(
        &requests,
        &engine,
        &parallel,
        AuthorizeDecisionBrief::from,
    );
}

#[library_benchmark(setup = setup_brief_128)]
fn authorize_brief_128((engine, parallel, requests): BenchCtx) {
    let _ = evaluate_batch_requests_for_bench(
        &requests,
        &engine,
        &parallel,
        AuthorizeDecisionBrief::from,
    );
}

#[library_benchmark(setup = setup_detailed_8)]
fn authorize_detailed_8((engine, parallel, requests): BenchCtx) {
    let _ = evaluate_batch_requests_for_bench(
        &requests,
        &engine,
        &parallel,
        AuthorizeDecisionDetailed::from,
    );
}

#[library_benchmark(setup = setup_detailed_32)]
fn authorize_detailed_32((engine, parallel, requests): BenchCtx) {
    let _ = evaluate_batch_requests_for_bench(
        &requests,
        &engine,
        &parallel,
        AuthorizeDecisionDetailed::from,
    );
}

#[library_benchmark(setup = setup_detailed_128)]
fn authorize_detailed_128((engine, parallel, requests): BenchCtx) {
    let _ = evaluate_batch_requests_for_bench(
        &requests,
        &engine,
        &parallel,
        AuthorizeDecisionDetailed::from,
    );
}

library_benchmark_group!(
    name = authorize_batch;
    benchmarks = authorize_brief_8,
        authorize_brief_32,
        authorize_brief_128,
        authorize_detailed_8,
        authorize_detailed_32,
        authorize_detailed_128
);

main!(library_benchmark_groups = authorize_batch);
