// Integration test for matrix expansion feature in CLI
#[cfg(test)]
mod matrix_expansion_tests {
    use treetop_rest::cli::matrix::expand_matrix;

    #[test]
    fn test_matrix_expansion_basic() {
        let queries = expand_matrix("alice|bob", "view|edit", "Photo", "photo1.jpg", vec![]);

        assert_eq!(queries.len(), 4, "Expected 2×2=4 queries");

        // Verify each principal appears twice (alice and bob, each with view and edit)
        let alice_queries: Vec<_> = queries
            .iter()
            .filter(|q| q.principal.contains("alice"))
            .collect();
        assert_eq!(alice_queries.len(), 2, "Expected 2 alice queries");

        let bob_queries: Vec<_> = queries
            .iter()
            .filter(|q| q.principal.contains("bob"))
            .collect();
        assert_eq!(bob_queries.len(), 2, "Expected 2 bob queries");

        // Verify all query IDs are unique
        let ids: Vec<_> = queries.iter().map(|q| q.query_id.clone()).collect();
        let unique_ids: std::collections::HashSet<_> = ids.iter().cloned().collect();
        assert_eq!(
            ids.len(),
            unique_ids.len(),
            "Expected all query IDs to be unique"
        );
    }

    #[test]
    fn test_matrix_expansion_with_brackets() {
        let queries = expand_matrix(
            "User::alice[admin|viewer]",
            "view",
            "Document",
            "doc1.pdf",
            vec![],
        );

        assert_eq!(queries.len(), 2, "Expected 2 bracket variations");

        // Verify bracket expansion preserved
        assert!(queries[0].principal.contains("[admin]"));
        assert!(queries[1].principal.contains("[viewer]"));
    }

    #[test]
    fn test_matrix_expansion_large_cartesian_product() {
        // 2 principals × 2 actions × 2 resources = 8 total
        let queries = expand_matrix(
            "alice|bob",
            "view|edit",
            "Photo",
            "photo1.jpg|photo2.jpg",
            vec![],
        );

        assert_eq!(queries.len(), 8, "Expected 2×2×2=8 queries");

        // Each combination should appear exactly once
        let combos: Vec<String> = queries
            .iter()
            .map(|q| format!("{}|{}|{}", q.principal, q.action, q.resource_id))
            .collect();

        for combo in &combos {
            let count = combos.iter().filter(|c| *c == combo).count();
            assert_eq!(count, 1, "Combination {} should appear exactly once", combo);
        }
    }

    #[test]
    fn test_matrix_query_id_generation() {
        let queries = expand_matrix("alice|bob", "view|edit", "Photo", "photo1.jpg", vec![]);

        // Query IDs should show only varying fields (principal and action vary, resource_id doesn't)
        // Expected format: "principal|action" (no #index suffix)
        assert!(
            queries[0].query_id.contains("alice"),
            "Query ID should contain principal, got: {}",
            queries[0].query_id
        );
        assert!(
            queries[0].query_id.contains("|"),
            "Query ID should contain pipe separator for multiple varying fields, got: {}",
            queries[0].query_id
        );

        // All query IDs should be different since combinations differ
        let ids: Vec<_> = queries.iter().map(|q| &q.query_id).collect();
        let unique: std::collections::HashSet<_> = ids.clone().into_iter().collect();
        assert_eq!(ids.len(), unique.len(), "All query IDs should be unique");
    }

    #[test]
    fn test_matrix_expansion_single_values_no_expansion() {
        let queries = expand_matrix("alice", "view", "Photo", "photo1.jpg", vec![]);

        assert_eq!(queries.len(), 1, "Single values should not expand");
        assert_eq!(queries[0].principal, "alice");
        assert_eq!(queries[0].action, "view");
    }

    #[test]
    fn test_matrix_with_attributes() {
        let attrs = vec![
            ("department".to_string(), "sales".to_string()),
            ("level".to_string(), "senior|junior".to_string()),
        ];

        let queries = expand_matrix("alice", "view", "Photo", "photo1.jpg", attrs);

        // 1 principal × 1 action × 1 resource × (1 dept × 2 levels) = 2 queries
        assert_eq!(
            queries.len(),
            2,
            "Expected 1×1×1×1×2=2 queries with attributes"
        );

        // Verify both level variations are present
        assert!(
            queries[0]
                .attrs
                .contains(&("level".to_string(), "senior".to_string()))
        );
        assert!(
            queries[1]
                .attrs
                .contains(&("level".to_string(), "junior".to_string()))
        );
    }
}
