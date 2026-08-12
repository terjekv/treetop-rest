#![no_main]

use libfuzzer_sys::fuzz_target;
use treetop_rest::handlers::evaluate_batch_requests_for_bench;
use treetop_rest::models::{
    AuthorizeDecisionBrief, AuthorizeDecisionDetailed, AuthorizeRequest, BatchResult, DecisionBrief,
};
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

const MAX_BATCH_SIZE: usize = 1024;

fn same_decision(left: &DecisionBrief, right: &DecisionBrief) -> bool {
    matches!(
        (left, right),
        (DecisionBrief::Allow, DecisionBrief::Allow) | (DecisionBrief::Deny, DecisionBrief::Deny)
    )
}

fuzz_target!(|data: &[u8]| {
    let Ok(request) = serde_json::from_slice::<AuthorizeRequest>(data) else {
        return;
    };
    if request.requests.len() > MAX_BATCH_SIZE {
        return;
    }

    let store = PolicyStore::new().expect("the fixed empty policy store must initialize");
    let parallel = ParallelConfig::new(1, 1, Some(8));

    let (brief, brief_successful, brief_failed) = evaluate_batch_requests_for_bench(
        &request.requests,
        &store.engine,
        &parallel,
        AuthorizeDecisionBrief::from,
    );
    let (detailed, detailed_successful, detailed_failed) = evaluate_batch_requests_for_bench(
        &request.requests,
        &store.engine,
        &parallel,
        AuthorizeDecisionDetailed::from,
    );

    assert_eq!(brief.len(), request.requests.len());
    assert_eq!(detailed.len(), request.requests.len());
    assert_eq!(brief_successful + brief_failed, request.requests.len());
    assert_eq!(
        detailed_successful + detailed_failed,
        request.requests.len()
    );
    assert_eq!(brief_successful, detailed_successful);
    assert_eq!(brief_failed, detailed_failed);

    for (index, ((input, brief), detailed)) in request
        .requests
        .iter()
        .zip(&brief)
        .zip(&detailed)
        .enumerate()
    {
        assert_eq!(brief.index(), index);
        assert_eq!(detailed.index(), index);
        assert_eq!(brief.id(), input.id.as_deref());
        assert_eq!(detailed.id(), input.id.as_deref());

        match (brief.result(), detailed.result()) {
            (BatchResult::Success { data: brief }, BatchResult::Success { data: detailed }) => {
                assert!(same_decision(&brief.decision, &detailed.decision))
            }
            (BatchResult::Failed { message: brief }, BatchResult::Failed { message: detailed }) => {
                assert_eq!(brief, detailed)
            }
            _ => panic!("brief and detailed evaluation disagreed on success"),
        }
    }
});
