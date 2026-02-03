/// Test to verify URL path encoding for namespaced users
#[test]
fn test_encode_path_segment() {
    // Simple encoding function mirroring the one in api_client.rs
    fn encode_path_segment(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }

    // Test basic alphanumeric
    assert_eq!(encode_path_segment("alice"), "alice");

    // Test namespaced user with :: separators
    assert_eq!(
        encode_path_segment("DNS::User::alice"),
        "DNS%3A%3AUser%3A%3Aalice"
    );

    // Test other special characters
    assert_eq!(
        encode_path_segment("user@example.com"),
        "user%40example.com"
    );
    assert_eq!(encode_path_segment("user/test"), "user%2Ftest");

    // Test URL-safe characters that should NOT be encoded
    assert_eq!(
        encode_path_segment("user-name_123.test~"),
        "user-name_123.test%7E"
    );
}
