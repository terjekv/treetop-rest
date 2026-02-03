//! CLI completion logic
//!
//! This module contains the tab completion logic used by the CLI REPL.
//! It's separated from the binary to make it testable.

// Top-level commands
pub const COMMANDS_MAIN: &[&str] = &[
    "status", "check", "policies", "upload", "json", "debug", "timing", "show", "version",
    "history", "metrics", "help", "exit",
];

// Global flags available for any command
pub const GLOBAL_FLAGS: &[&str] = &[
    "--table-style",
    "--json",
    "--debug",
    "--timing",
    "--host",
    "--port",
];

// Table style options
pub const TABLE_STYLES: &[&str] = &["ascii", "rounded", "unicode", "markdown"];

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

pub const POLICIES_FLAGS: &[&str] = &["--user", "--raw"];

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

    // Check if the previous token was a flag that expects a value
    if !tokens.is_empty() {
        let last_token = tokens[tokens.len() - 1];
        if last_token == "--table-style" {
            // Complete with table style options
            let mut matches = Vec::new();
            for style in TABLE_STYLES {
                if style.starts_with(word) {
                    matches.push(style.to_string());
                }
            }
            return (start, matches);
        }
    }

    // Decide suggestions based on first token and collect all relevant flags
    let mut all_candidates = GLOBAL_FLAGS.to_vec();

    if !tokens.is_empty() {
        match tokens[0] {
            "check" => all_candidates.extend_from_slice(CHECK_FLAGS),
            "policies" => all_candidates.extend_from_slice(POLICIES_FLAGS),
            "upload" => all_candidates.extend_from_slice(UPLOAD_FLAGS),
            _ => {}
        }
    } else {
        // At top level, suggest commands
        let mut matches = Vec::new();
        for cmd in COMMANDS_MAIN {
            if cmd.starts_with(word) {
                matches.push(cmd.to_string());
            }
        }
        return (start, matches);
    }

    // Filter out flags/commands that have already been used, except repeatable ones
    let used = tokens.to_vec();
    let candidates = all_candidates
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
        // Should include both global flags and check-specific flags
        assert!(completions.contains(&"--principal".to_string()));
        assert!(completions.contains(&"--table-style".to_string()));
    }

    #[test]
    fn test_complete_table_style_values() {
        let (start, completions) = complete_line("check --table-style ", 20);
        assert_eq!(start, 20);
        assert_eq!(
            completions,
            TABLE_STYLES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_complete_table_style_partial() {
        let (start, completions) = complete_line("check --table-style a", 21);
        assert_eq!(start, 20);
        assert_eq!(completions, vec!["ascii"]);
    }

    #[test]
    fn test_repeatable_flag_remains() {
        let (start, completions) = complete_line("check --resource-attribute key=val --", 37);
        assert_eq!(start, 35);
        assert!(completions.contains(&"--resource-attribute".to_string()));
        assert!(completions.contains(&"--detailed".to_string()));
    }
}
