#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::json;
use treetop_rest::state::PolicyStore;

const BASELINE_POLICY: &str = "permit (principal, action, resource);";

fn snapshot(store: &PolicyStore) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "engine_version": store.engine.current_version(),
        "policies": &store.policies,
        "labels": &store.labels,
        "schema": &store.schema,
        "request_context": store.request_context_status,
    }))
    .expect("policy state must remain serializable")
}

fuzz_target!(|data: &[u8]| {
    let Some((&kind, body)) = data.split_first() else {
        return;
    };
    let Ok(content) = std::str::from_utf8(body) else {
        return;
    };

    let mut store = PolicyStore::new().expect("the fixed empty policy store must initialize");
    store
        .set_dsl(BASELINE_POLICY, None, None)
        .expect("the fixed baseline policy must compile");
    let before = snapshot(&store);

    let update = match kind {
        b'p' => store.set_dsl(content, None, None),
        b's' => store.set_schema(content, None, None),
        b'l' => store.set_labels(content, None, None),
        _ => return,
    };

    if update.is_err() {
        assert_eq!(snapshot(&store), before);
    }
});
