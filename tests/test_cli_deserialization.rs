use treetop_rest::cli::models::{AuthCheckResult, AuthorizeResult, CliDisplay, UserPolicies};

#[test]
fn test_cli_deserialize_detailed_response() {
    let json_str = r#"{
  "results": [{
    "index": 0,
    "id": "check-1",
    "status": "success",
    "result": {
      "policy": [{
        "literal": "permit (\n    principal == User::\"alice\",\n    action == Action::\"view\",\n    resource == Photo::\"VacationPhoto94.jpg\"\n);",
        "json": {
          "effect": "permit",
          "principal": {"op": "==", "entity": {"type": "User", "id": "alice"}},
          "action": {"op": "==", "entity": {"type": "Action", "id": "view"}},
          "resource": {"op": "==", "entity": {"type": "Photo", "id": "VacationPhoto94.jpg"}},
          "conditions": []
        },
        "annotation_id": null,
        "cedar_id": "policy0"
      }],
      "decision": "Allow",
      "version": {
        "hash": "0934b93f44c034078a0efa66ee45115321de807370d793c83318655c29c815d3",
        "loaded_at": "2026-02-03T09:30:59.873720000Z"
      }
    }
  }]
}"#;

    match serde_json::from_str::<AuthorizeResult>(json_str) {
        Ok(result) => {
            println!("✓ Successfully deserialized response");
            assert_eq!(result.results.len(), 1);
            let first = &result.results[0];
            assert_eq!(first.index, 0);
            assert_eq!(first.id, Some("check-1".to_string()));
            assert_eq!(first.status, "success");
            assert!(first.result.is_some());

            if let Some(AuthCheckResult::Detailed(detailed)) = &first.result {
                println!("✓ Correctly parsed as Detailed response");
                println!("  - Policies count: {}", detailed.policy.len());
                assert!(!detailed.policy.is_empty());
                println!("  - First policy literal: {}", detailed.policy[0].literal);
            } else {
                panic!("Expected Detailed variant");
            }
        }
        Err(e) => {
            panic!("Failed to deserialize: {}", e);
        }
    }
}
#[test]
fn test_cli_deserialize_single_policy_object() {
    // Test case for when server returns policy as a single object instead of array
    // This is what happens with the production server
    let json_str = r#"{
  "results": [{
    "index": 0,
    "id": "check-1",
    "status": "success",
    "result": {
      "policy": {
        "literal": "permit (\n    principal == User::\"alice\",\n    action == Action::\"view\",\n    resource == Photo::\"VacationPhoto94.jpg\"\n);",
        "json": {
          "effect": "permit",
          "principal": {"op": "==", "entity": {"type": "User", "id": "alice"}},
          "action": {"op": "==", "entity": {"type": "Action", "id": "view"}},
          "resource": {"op": "==", "entity": {"type": "Photo", "id": "VacationPhoto94.jpg"}},
          "conditions": []
        },
        "annotation_id": null,
        "cedar_id": "policy0"
      },
      "decision": "Allow",
      "version": {
        "hash": "0934b93f44c034078a0efa66ee45115321de807370d793c83318655c29c815d3",
        "loaded_at": "2026-02-03T09:30:59.873720000Z"
      }
    }
  }]
}"#;

    match serde_json::from_str::<AuthorizeResult>(json_str) {
        Ok(result) => {
            println!("✓ Successfully deserialized single policy object response");
            assert_eq!(result.results.len(), 1);
            let first = &result.results[0];
            assert_eq!(first.index, 0);
            assert_eq!(first.id, Some("check-1".to_string()));
            assert_eq!(first.status, "success");
            assert!(first.result.is_some());

            if let Some(AuthCheckResult::Detailed(detailed)) = &first.result {
                println!("✓ Correctly parsed single policy as array with one element");
                println!("  - Policies count: {}", detailed.policy.len());
                assert_eq!(
                    detailed.policy.len(),
                    1,
                    "Single policy should be wrapped in array"
                );
                println!("  - First policy literal: {}", detailed.policy[0].literal);
            } else {
                panic!("Expected Detailed variant");
            }
        }
        Err(e) => {
            panic!("Failed to deserialize: {}", e);
        }
    }
}

#[test]
fn test_cli_deserialize_user_policies_with_matches() {
    let json_str = r#"{
  "user": "alice",
  "policies": [
    {"effect": "permit"},
    {"effect": "permit"}
  ],
  "matches": [
    {
      "cedar_id": "policy0",
      "reasons": ["PrincipalEq", "ResourceIs"]
    },
    {
      "cedar_id": "policy1",
      "reasons": ["PrincipalIn"]
    }
  ]
}"#;

    let result: UserPolicies =
        serde_json::from_str(json_str).expect("Expected valid user policies");
    assert_eq!(result.user, "alice");
    assert_eq!(result.policies.len(), 2);
    assert_eq!(result.matches.len(), 2);
    assert_eq!(result.matches[0].cedar_id, "policy0");
    assert_eq!(result.matches[0].reasons.len(), 2);
}

#[test]
fn test_cli_deserialize_user_policies_without_matches() {
    let json_str = r#"{
  "user": "alice",
  "policies": [
    {"effect": "permit"}
  ]
}"#;

    let result: UserPolicies =
        serde_json::from_str(json_str).expect("Expected user policies without matches");
    assert_eq!(result.user, "alice");
    assert_eq!(result.policies.len(), 1);
    assert!(result.matches.is_empty());
}

#[test]
fn test_cli_display_user_policies_includes_reasons() {
    let json_str = r#"{
  "user": "alice",
  "policies": [
    {"effect": "permit"}
  ],
  "matches": [
    {
      "cedar_id": "policy0",
      "reasons": ["PrincipalEq", "ResourceIs"]
    }
  ]
}"#;

    let result: UserPolicies =
        serde_json::from_str(json_str).expect("Expected valid user policies");
    let display = result.display();

    assert!(display.contains("User: alice"));
    assert!(display.contains("Policies: 1"));
    assert!(display.contains("policy0"));
    assert!(display.contains("PrincipalEq"));
    assert!(display.contains("ResourceIs"));
}
