use std::str::FromStr;
use std::sync::Arc;
use treetop_core::{Action, Principal, Request, Resource, User};
use treetop_rest::handlers::evaluate_batch_requests_for_bench;
use treetop_rest::models::{AuthorizeDecisionBrief, AuthorizeDecisionDetailed, AuthRequest};
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

pub fn bench_brief(count: usize) {
    let engine = build_engine();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let requests = build_requests(count);
    let _ = evaluate_batch_requests_for_bench(
        &requests,
        &engine,
        &parallel,
        AuthorizeDecisionBrief::from,
    );
}

pub fn bench_detailed(count: usize) {
    let engine = build_engine();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let requests = build_requests(count);
    let _ = evaluate_batch_requests_for_bench(
        &requests,
        &engine,
        &parallel,
        AuthorizeDecisionDetailed::from,
    );
}
