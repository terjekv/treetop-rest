//! Tests for CLI command parsing and tab completion
//!
//! This test suite validates:
//! - Command completion at various input positions
//! - Flag completion for different subcommands
//! - Filtering of non-repeatable flags after use
//! - Preservation of repeatable flags (like --resource-attribute)
//! - Edge cases (empty input, partial matches, invalid contexts)
//!
//! These tests use the actual completion logic from src/cli.rs

use rstest::rstest;
use treetop_rest::cli;

/// Wrapper around the real CLI completion logic
fn get_completions(line: &str, pos: usize) -> Vec<String> {
    let (_start, completions) = cli::complete_line(line, pos);
    completions
}

#[rstest]
#[case("", 0, vec!["status", "check", "policies", "upload", "json", "debug", "timing", "show", "version", "history", "metrics", "help", "exit"])]
#[case("s", 1, vec!["status", "show"])]
#[case("st", 2, vec!["status"])]
#[case("sta", 3, vec!["status"])]
#[case("c", 1, vec!["check"])]
#[case("v", 1, vec!["version"])]
#[case("p", 1, vec!["policies"])]
#[case("po", 2, vec!["policies"])]
fn test_command_completion(#[case] input: &str, #[case] pos: usize, #[case] expected: Vec<&str>) {
    let completions = get_completions(input, pos);
    assert_eq!(completions, expected);
}

#[rstest]
#[case("check ", 6, vec!["--table-style", "--json", "--debug", "--timing", "--host", "--port", "--principal", "--action", "--resource-type", "--resource-id", "--resource-attribute", "--detailed"])]
#[case("check --", 8, vec!["--table-style", "--json", "--debug", "--timing", "--host", "--port", "--principal", "--action", "--resource-type", "--resource-id", "--resource-attribute", "--detailed"])]
#[case("check --p", 9, vec!["--port", "--principal"])]
#[case("check --pr", 10, vec!["--principal"])]
#[case("check --a", 9, vec!["--action"])]
#[case("check --r", 9, vec!["--resource-type", "--resource-id", "--resource-attribute"])]
#[case("check --re", 10, vec!["--resource-type", "--resource-id", "--resource-attribute"])]
#[case("check --res", 11, vec!["--resource-type", "--resource-id", "--resource-attribute"])]
#[case("check --reso", 12, vec!["--resource-type", "--resource-id", "--resource-attribute"])]
#[case("check --resou", 13, vec!["--resource-type", "--resource-id", "--resource-attribute"])]
#[case("check --resour", 14, vec!["--resource-type", "--resource-id", "--resource-attribute"])]
#[case("check --resource", 16, vec!["--resource-type", "--resource-id", "--resource-attribute"])]
#[case("check --resource-", 17, vec!["--resource-type", "--resource-id", "--resource-attribute"])]
#[case("check --resource-t", 18, vec!["--resource-type"])]
#[case("check --resource-ty", 19, vec!["--resource-type"])]
#[case("check --resource-i", 18, vec!["--resource-id"])]
#[case("check --resource-a", 18, vec!["--resource-attribute"])]
#[case("check --d", 9, vec!["--debug", "--detailed"])]
fn test_check_flag_completion(
    #[case] input: &str,
    #[case] pos: usize,
    #[case] expected: Vec<&str>,
) {
    let completions = get_completions(input, pos);
    assert_eq!(completions, expected);
}

#[rstest]
#[case("check --principal alice ", 24)]
#[case("check --principal alice --action view ", 38)]
fn test_flags_filtered_after_use(#[case] input: &str, #[case] pos: usize) {
    let completions = get_completions(input, pos);

    // --principal and --action should not appear again after being used
    assert!(!completions.contains(&"--principal".to_string()));
    if input.contains("--action") {
        assert!(!completions.contains(&"--action".to_string()));
    }
}

#[rstest]
#[case("check --resource-attribute key=value ", 37)]
#[case(
    "check --resource-attribute key=value --resource-attribute key2=value2 ",
    70
)]
fn test_repeatable_flag_completion(#[case] input: &str, #[case] pos: usize) {
    let completions = get_completions(input, pos);

    // --resource-attribute should still be available after being used
    assert!(completions.contains(&"--resource-attribute".to_string()));
}

#[rstest]
#[case("policies ", 9, vec!["--table-style", "--json", "--debug", "--timing", "--host", "--port", "--user", "--raw"])]
#[case("policies --", 11, vec!["--table-style", "--json", "--debug", "--timing", "--host", "--port", "--user", "--raw"])]
#[case("policies --r", 12, vec!["--raw"])]
#[case("policies --u", 12, vec!["--user"])]
fn test_policies_completion(
    #[case] input: &str,
    #[case] pos: usize,
    #[case] expected: Vec<&str>,
) {
    let completions = get_completions(input, pos);
    assert_eq!(completions, expected);
}

#[rstest]
#[case("upload ", 7, vec!["--table-style", "--json", "--debug", "--timing", "--host", "--port", "--file", "--raw", "--token"])]
#[case("upload --", 9, vec!["--table-style", "--json", "--debug", "--timing", "--host", "--port", "--file", "--raw", "--token"])]
#[case("upload --f", 10, vec!["--file"])]
#[case("upload --r", 10, vec!["--raw"])]
#[case("upload --t", 10, vec!["--table-style", "--timing", "--token"])]
fn test_upload_completion(#[case] input: &str, #[case] pos: usize, #[case] expected: Vec<&str>) {
    let completions = get_completions(input, pos);
    assert_eq!(completions, expected);
}

#[test]
fn test_no_completion_for_unknown_command() {
    let completions = get_completions("unknown ", 8);
    // Unknown commands still get global flags
    assert!(completions.contains(&"--table-style".to_string()));
    assert!(completions.len() == treetop_rest::cli::completion::GLOBAL_FLAGS.len());
}

#[test]
fn test_policies_with_user() {
    // policies with --user should work with the new syntax
    let completions = get_completions("policies --user ", 16);
    // Should get global flags and the --raw flag alongside --user
    assert!(completions.contains(&"--raw".to_string()));
}

#[test]
fn test_completion_at_beginning_of_word() {
    let completions = get_completions("c", 1);
    assert_eq!(completions, vec!["check"]);
}

#[test]
fn test_completion_with_partial_match() {
    let completions = get_completions("chec", 4);
    assert_eq!(completions, vec!["check"]);
}

#[test]
fn test_completion_starting_with_p() {
    let completions = get_completions("p", 1);
    assert_eq!(completions, vec!["policies"]);
}

#[test]
fn test_multiple_commands_starting_with_same_letter() {
    let completions = get_completions("", 0);
    // Should include both 'status' and others
    assert!(completions.contains(&"status".to_string()));
    assert!(completions.contains(&"check".to_string()));
    assert!(completions.len() == treetop_rest::cli::completion::COMMANDS_MAIN.len()); // All main commands
}

// Test command parsing by checking clap would accept these
mod command_parsing {
    use clap::Parser;

    // Minimal CLI structure for testing
    #[derive(Parser, Debug)]
    #[clap(name = "test-cli")]
    struct TestCli {
        #[clap(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand, Debug, Clone)]
    enum TestCommands {
        Status,
        Check {
            #[clap(long)]
            principal: String,
            #[clap(long)]
            action: String,
            #[clap(long = "resource-type")]
            resource_type: String,
            #[clap(long = "resource-id")]
            resource_id: String,
        },
        GetPolicies {
            #[clap(long)]
            raw: bool,
        },
    }

    #[test]
    fn test_parse_status_command() {
        let args = vec!["test-cli", "status"];
        let cli = TestCli::try_parse_from(args);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_parse_check_command() {
        let args = vec![
            "test-cli",
            "check",
            "--principal",
            "alice",
            "--action",
            "view",
            "--resource-type",
            "Photo",
            "--resource-id",
            "photo.jpg",
        ];
        let cli = TestCli::try_parse_from(args);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_parse_get_policies_command() {
        let args = vec!["test-cli", "get-policies", "--raw"];
        let cli = TestCli::try_parse_from(args);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_parse_get_policies_without_flag() {
        let args = vec!["test-cli", "get-policies"];
        let cli = TestCli::try_parse_from(args);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_parse_fails_with_missing_required_args() {
        let args = vec!["test-cli", "check", "--principal", "alice"];
        let cli = TestCli::try_parse_from(args);
        assert!(cli.is_err());
    }

    #[test]
    fn test_parse_fails_with_unknown_command() {
        let args = vec!["test-cli", "unknown"];
        let cli = TestCli::try_parse_from(args);
        assert!(cli.is_err());
    }
}
