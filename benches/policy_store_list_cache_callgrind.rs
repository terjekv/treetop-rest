use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_rest::state::PolicyStore;

struct ListContext {
    store: PolicyStore,
    user: String,
    groups: Vec<String>,
    namespaces: Vec<String>,
}

fn build_large_store() -> PolicyStore {
    let mut dsl = String::new();
    for index in 0..100 {
        dsl.push_str(&format!(
            r#"
@id("list.cache.{index}")
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"photo_{index}.jpg"
);
"#,
        ));
    }

    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(&dsl, None, None).unwrap();
    store
}

fn setup_context() -> ListContext {
    ListContext {
        store: build_large_store(),
        user: "alice".to_string(),
        groups: Vec::new(),
        namespaces: Vec::new(),
    }
}

fn setup_raw_hit() -> ListContext {
    let context = setup_context();
    context
        .store
        .list_policies_raw(
            context.user.clone(),
            context.groups.clone(),
            context.namespaces.clone(),
        )
        .unwrap();
    context
}

fn setup_json_hit() -> ListContext {
    let context = setup_context();
    context
        .store
        .list_policies_json(
            context.user.clone(),
            context.groups.clone(),
            context.namespaces.clone(),
        )
        .unwrap();
    context
}

fn teardown_context(_: ListContext) {}

#[library_benchmark(setup = setup_context, teardown = teardown_context)]
fn list_raw_cache_miss(mut context: ListContext) -> ListContext {
    black_box(
        context
            .store
            .list_policies_raw(
                std::mem::take(&mut context.user),
                std::mem::take(&mut context.groups),
                std::mem::take(&mut context.namespaces),
            )
            .unwrap(),
    );
    context
}

#[library_benchmark(setup = setup_raw_hit, teardown = teardown_context)]
fn list_raw_cache_hit(mut context: ListContext) -> ListContext {
    black_box(
        context
            .store
            .list_policies_raw(
                std::mem::take(&mut context.user),
                std::mem::take(&mut context.groups),
                std::mem::take(&mut context.namespaces),
            )
            .unwrap(),
    );
    context
}

#[library_benchmark(setup = setup_context, teardown = teardown_context)]
fn list_json_cache_miss(mut context: ListContext) -> ListContext {
    black_box(
        context
            .store
            .list_policies_json(
                std::mem::take(&mut context.user),
                std::mem::take(&mut context.groups),
                std::mem::take(&mut context.namespaces),
            )
            .unwrap(),
    );
    context
}

#[library_benchmark(setup = setup_json_hit, teardown = teardown_context)]
fn list_json_cache_hit(mut context: ListContext) -> ListContext {
    black_box(
        context
            .store
            .list_policies_json(
                std::mem::take(&mut context.user),
                std::mem::take(&mut context.groups),
                std::mem::take(&mut context.namespaces),
            )
            .unwrap(),
    );
    context
}

library_benchmark_group!(
    name = policy_store_list_cache;
    benchmarks = list_raw_cache_miss, list_raw_cache_hit, list_json_cache_miss, list_json_cache_hit
);

main!(library_benchmark_groups = policy_store_list_cache);
