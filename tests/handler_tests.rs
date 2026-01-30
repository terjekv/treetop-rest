use actix_web::{App, test, web};
use rstest::rstest;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use treetop_core::{Action, AttrValue, Principal, Request, Resource, User};
use treetop_rest::handlers;
use treetop_rest::models::{
    AuthorizeBriefResponse, AuthorizeDecisionBrief, AuthorizeDetailedResponse, AuthorizeRequest,
    BatchResult, DecisionBrief, IndexedResult, PoliciesMetadata,
};
use treetop_rest::state::PolicyStore;

/// Helper to create a test policy store with default policies
fn create_test_store() -> Arc<Mutex<PolicyStore>> {
    let mut store = PolicyStore::new().unwrap();

    let dsl = r#"
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

    store.set_dsl(dsl, None, None).unwrap();
    Arc::new(Mutex::new(store))
}

fn assert_brief_result(
    result: &IndexedResult<AuthorizeDecisionBrief>,
    expected_id: Option<&str>,
    expected: DecisionBrief,
) {
    if let Some(expected_id) = expected_id {
        assert_eq!(result.id(), Some(expected_id));
    }
    match result.result() {
        BatchResult::Success { data } => match expected {
            DecisionBrief::Allow => assert!(matches!(data.decision, DecisionBrief::Allow)),
            DecisionBrief::Deny => assert!(matches!(data.decision, DecisionBrief::Deny)),
        },
        BatchResult::Failed { message } => panic!("unexpected failure: {}", message),
    }
}

fn assert_single_decision(body: &AuthorizeBriefResponse, expected: DecisionBrief) {
    assert_eq!(body.results().len(), 1);
    let result = body.iter().next().expect("missing result");
    assert_brief_result(result, None, expected);
}

#[actix_web::test]
async fn test_health_endpoint() {
    let app =
        test::init_service(App::new().route("/api/v1/health", web::get().to(handlers::health)))
            .await;

    let req = test::TestRequest::get().uri("/api/v1/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_get_status_endpoint() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/status", web::get().to(handlers::get_status)),
    )
    .await;

    let req = test::TestRequest::get().uri("/api/v1/status").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body: PoliciesMetadata = test::read_body_json(resp).await;
    assert_eq!(body.policies.entries, 3);
}

#[actix_web::test]
async fn test_check_endpoint_allow() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg"),
    };

    let auth_request = AuthorizeRequest::single(request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_single_decision(&body, DecisionBrief::Allow);
}

#[actix_web::test]
async fn test_check_endpoint_deny() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("edit").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg"),
    };

    let auth_request = AuthorizeRequest::single(request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_single_decision(&body, DecisionBrief::Deny);
}

#[actix_web::test]
async fn test_check_endpoint_with_attributes() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let resource = Resource::new("Host", "myhost.example.com")
        .with_attr("ip", AttrValue::Ip("10.0.0.5".to_string()));

    let request = Request {
        principal: Principal::User(User::from_str("bob").unwrap()),
        action: Action::from_str("create_host").unwrap(),
        resource,
    };

    let auth_request = AuthorizeRequest::single(request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_single_decision(&body, DecisionBrief::Allow);
}

#[actix_web::test]
async fn test_check_endpoint_deny_out_of_range() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let resource = Resource::new("Host", "myhost.example.com")
        .with_attr("ip", AttrValue::Ip("192.168.1.5".to_string()));

    let request = Request {
        principal: Principal::User(User::from_str("bob").unwrap()),
        action: Action::from_str("create_host").unwrap(),
        resource,
    };

    let auth_request = AuthorizeRequest::single(request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_single_decision(&body, DecisionBrief::Deny);
}

#[actix_web::test]
async fn test_get_policies_json() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/policies", web::get().to(handlers::get_policies)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/policies")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
}

#[actix_web::test]
async fn test_get_policies_raw() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/policies", web::get().to(handlers::get_policies)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/policies?format=raw")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");

    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(body_str.contains("permit"));
}

#[actix_web::test]
async fn test_upload_policies_not_allowed() {
    let store = create_test_store();
    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies",
        web::post().to(handlers::upload_policies),
    ))
    .await;

    let new_policy = r#"{"policies": "permit (principal, action, resource);"}"#;

    let req = test::TestRequest::post()
        .uri("/api/v1/policies")
        .set_payload(new_policy)
        .insert_header(("content-type", "application/json"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should fail because upload is not allowed
    assert!(!resp.status().is_success());
}

#[rstest]
#[case("test-token", "test-token", true)]
#[case("correct-token", "correct-token", true)]
#[case("correct-token", "wrong-token", false)]
#[case("secret123", "wrong123", false)]
#[actix_web::test]
async fn test_upload_with_token(
    #[case] expected_token: &str,
    #[case] provided_token: &str,
    #[case] should_succeed: bool,
) {
    let store = create_test_store();
    {
        let mut store_guard = store.lock().unwrap();
        store_guard.allow_upload = true;
        store_guard.upload_token = Some(expected_token.to_string());
    }

    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies",
        web::post().to(handlers::upload_policies),
    ))
    .await;

    let new_policy = r#"{"policies": "permit (principal, action, resource);"}"#;

    let req = test::TestRequest::post()
        .uri("/api/v1/policies")
        .set_payload(new_policy)
        .insert_header(("content-type", "application/json"))
        .insert_header(("X-Upload-Token", provided_token))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().is_success(), should_succeed);
}

#[actix_web::test]
async fn test_list_policies_for_user() {
    let store = create_test_store();
    let app = test::init_service(App::new().app_data(web::Data::new(store)).route(
        "/api/v1/policies/{user}",
        web::get().to(handlers::list_policies),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/policies/alice")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_authorize_endpoint_brief() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request1 = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg"),
    };

    let request2 = Request {
        principal: Principal::User(User::from_str("bob").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg"),
    };

    let auth_request = AuthorizeRequest::with_ids([("check-1", request1), ("check-2", request2)]);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=brief")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeBriefResponse = test::read_body_json(resp).await;
    assert_eq!(body.results().len(), 2);

    let mut results = body.iter();
    assert_brief_result(
        results.next().expect("missing result"),
        Some("check-1"),
        DecisionBrief::Allow,
    );
    // Second request should be a Deny (bob doesn't have view on this photo)
    assert_brief_result(
        results.next().expect("missing result"),
        Some("check-2"),
        DecisionBrief::Deny,
    );
    assert_eq!(body.successes(), 2);
    assert_eq!(body.failures(), 0);
}

#[actix_web::test]
async fn test_authorize_endpoint_detailed() {
    let store = create_test_store();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg"),
    };

    let auth_request = AuthorizeRequest::new().add_with_id("check-1", request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=full")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: AuthorizeDetailedResponse = test::read_body_json(resp).await;
    assert_eq!(body.results().len(), 1);
    match body.iter().next().expect("missing result").result() {
        BatchResult::Success { data } => {
            assert!(matches!(data.desicion, DecisionBrief::Allow));
            assert!(data.policy.is_some());
        }
        BatchResult::Failed { message } => panic!("unexpected failure: {}", message),
    }
}
