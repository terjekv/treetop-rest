//! CLI completion logic
//!
//! This module contains the tab completion logic used by the CLI REPL.
//! It's separated from the binary to make it testable.

// Top-level commands
pub const COMMANDS_MAIN: &[&str] = &[
    "status",
    "version",
    "check",
    "get-policies",
    "upload",
    "list-policies",
    "json",
    "debug",
    "timing",
    "history",
    "help",
    "exit",
];

// Flags per command (use kebab-case to match clap defaults)
pub const CHECK_FLAGS: &[&str] = &[
    "--principal",
    "--action",
    "--resource-type",
    "--resource-id",
    "--resource-attribute",
    "--detailed",
];

// Flags that can be used multiple times
pub const REPEATABLE_FLAGS: &[&str] = &["--resource-attribute"];

pub const GET_POLICIES_FLAGS: &[&str] = &["--raw"];

pub const UPLOAD_FLAGS: &[&str] = &["--file", "--raw", "--token"];

/// Extract completion logic for testability
/// Returns (start_position, matching_completions)
pub fn complete_line(line: &str, pos: usize) -> (usize, Vec<String>) {
    // Determine start of current token
    let start = line[..pos].rfind(' ').map_or(0, |i| i + 1);
    let word = &line[start..pos];
    // Split the input into tokens before the current word
    let prefix = &line[..start].trim();
    let tokens: Vec<&str> = if prefix.is_empty() {
        vec![]
    } else {
        prefix.split_whitespace().collect()
    };

    // Decide suggestions based on first token
    let base = if tokens.is_empty() {
        COMMANDS_MAIN
    } else {
        match tokens[0] {
            "check" => CHECK_FLAGS,
            "get-policies" => GET_POLICIES_FLAGS,
            "upload" => UPLOAD_FLAGS,
            _ => &[],
        }
    };

    // Filter out flags/commands that have already been used, except repeatable ones
    let used = tokens.to_vec();
    let candidates = base
        .iter()
        .filter(|&&item| !used.contains(&item) || REPEATABLE_FLAGS.contains(&item))
        .cloned()
        .collect::<Vec<&str>>();

    // Build completion pairs matching the current word
    let mut matches = Vec::new();
    for s in candidates {
        if s.starts_with(word) {
            matches.push(s.to_string());
        }
    }
    (start, matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_empty() {
        let (start, completions) = complete_line("", 0);
        assert_eq!(start, 0);
        assert_eq!(completions.len(), COMMANDS_MAIN.len());
    }

    #[test]
    fn test_complete_check() {
        let (start, completions) = complete_line("che", 3);
        assert_eq!(start, 0);
        assert_eq!(completions, vec!["check"]);
    }

    #[test]
    fn test_complete_check_flags() {
        let (start, completions) = complete_line("check --", 8);
        assert_eq!(start, 6);
        assert_eq!(completions.len(), CHECK_FLAGS.len());
    }

    #[test]
    fn test_repeatable_flag_remains() {
        let (start, completions) = complete_line("check --resource-attribute key=val --", 37);
        assert_eq!(start, 35);
        // --resource-attribute should still be in the list because it's repeatable
        assert!(completions.contains(&"--resource-attribute".to_string()));
        // But it hasn't filtered other unused flags yet - they're all available
        assert!(completions.contains(&"--detailed".to_string()));
    }
}
