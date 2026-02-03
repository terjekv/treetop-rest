/// Test to verify principal parsing with groups
#[test]
fn test_parse_principal_with_groups() {
    // Simple parsing function mirroring the one in cli.rs
    fn parse_principal_with_groups(user_str: &str) -> (String, Vec<String>) {
        if let Some(bracket_pos) = user_str.find('[') {
            if let Some(close_pos) = user_str.find(']') {
                if close_pos > bracket_pos {
                    let principal_part = user_str[..bracket_pos].to_string();
                    let groups_str = &user_str[bracket_pos + 1..close_pos];

                    let groups: Vec<String> = groups_str
                        .split(',')
                        .map(|g| g.trim().to_string())
                        .filter(|g| !g.is_empty())
                        .collect();

                    return (principal_part, groups);
                }
            }
        }

        // No brackets, return full principal as-is
        (user_str.to_string(), vec![])
    }

    // Test simple user without namespace
    let (principal, groups) = parse_principal_with_groups("alice");
    assert_eq!(principal, "alice");
    assert_eq!(groups, Vec::<String>::new());

    // Test simple user with groups
    let (principal, groups) = parse_principal_with_groups("alice[admins,users]");
    assert_eq!(principal, "alice");
    assert_eq!(groups, vec!["admins", "users"]);

    // Test namespaced user without groups
    let (principal, groups) = parse_principal_with_groups("DNS::User::alice");
    assert_eq!(principal, "DNS::User::alice");
    assert_eq!(groups, Vec::<String>::new());

    // Test namespaced user with groups
    let (principal, groups) = parse_principal_with_groups("DNS::User::alice[admins,users]");
    assert_eq!(principal, "DNS::User::alice");
    assert_eq!(groups, vec!["admins", "users"]);

    // Test User::alice format
    let (principal, groups) = parse_principal_with_groups("User::alice[dev]");
    assert_eq!(principal, "User::alice");
    assert_eq!(groups, vec!["dev"]);

    // Test with spaces in groups
    let (principal, groups) = parse_principal_with_groups("alice[group1, group2 , group3]");
    assert_eq!(principal, "alice");
    assert_eq!(groups, vec!["group1", "group2", "group3"]);
}
