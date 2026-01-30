/// Matrix expansion module for generating test permutations

#[derive(Debug, Clone)]
pub struct MatrixQuery {
    pub principal: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub attrs: Vec<(String, String)>,
    pub query_id: String,
}

/// Parses matrix syntax with alternations
/// Supports:
/// - `value1|value2|value3` → simple list expansion
/// - `prefix[alt1|alt2]suffix` → bracket expansion for Cedar entities
fn parse_alternatives(input: &str) -> Vec<String> {
    // First, split on pipes that are NOT inside brackets
    let mut segments = Vec::new();
    let mut current_segment = String::new();
    let mut bracket_depth = 0;
    let mut escape_next = false;

    for ch in input.chars() {
        if escape_next {
            current_segment.push(ch);
            escape_next = false;
        } else if ch == '\\' {
            escape_next = true;
        } else if ch == '[' {
            bracket_depth += 1;
            current_segment.push(ch);
        } else if ch == ']' {
            bracket_depth -= 1;
            current_segment.push(ch);
        } else if ch == '|' && bracket_depth == 0 {
            // This is a top-level pipe separator
            if !current_segment.is_empty() {
                segments.push(current_segment.clone());
            }
            current_segment.clear();
        } else {
            current_segment.push(ch);
        }
    }

    if !current_segment.is_empty() {
        segments.push(current_segment);
    }

    // If no pipes were found, process the whole input for brackets
    if segments.is_empty() {
        return expand_brackets(input);
    }

    // Process each segment for bracket expansion and collect all results
    let mut all_results = Vec::new();
    for segment in segments {
        let expanded = expand_brackets(&segment);
        all_results.extend(expanded);
    }

    all_results
}

/// Expands bracket notation within a single segment
/// `prefix[opt1|opt2]suffix` → `prefixopt1suffix`, `prefixopt2suffix`
fn expand_brackets(segment: &str) -> Vec<String> {
    if !segment.contains('[') {
        return vec![segment.to_string()];
    }

    let mut results = vec![String::new()];
    let mut current_pos = 0;
    let chars: Vec<char> = segment.chars().collect();

    while current_pos < chars.len() {
        if chars[current_pos] == '[' {
            // Find matching ]
            let mut bracket_depth = 1;
            let start = current_pos + 1;
            let mut end = start;

            for (i, ch) in chars.iter().enumerate().skip(start) {
                if *ch == '[' {
                    bracket_depth += 1;
                } else if *ch == ']' {
                    bracket_depth -= 1;
                    if bracket_depth == 0 {
                        end = i;
                        break;
                    }
                }
            }

            let bracket_content: String = chars[start..end].iter().collect();
            let alternatives: Vec<String> = bracket_content
                .split('|')
                .map(|opt| format!("[{}]", opt.trim()))
                .collect();

            // Multiply results by alternatives
            let mut new_results = Vec::new();
            for result in results {
                for alt in &alternatives {
                    new_results.push(result.clone() + alt);
                }
            }
            results = new_results;

            current_pos = end + 1;
        } else {
            // Regular character
            for result in &mut results {
                result.push(chars[current_pos]);
            }
            current_pos += 1;
        }
    }

    results
}

/// Generates meaningful query IDs showing only differentiating fields
fn generate_smart_query_ids(queries: &mut [MatrixQuery]) {
    // Determine which fields vary across queries
    let has_multiple_principals = queries
        .iter()
        .map(|q| &q.principal)
        .collect::<std::collections::HashSet<_>>()
        .len()
        > 1;
    let has_multiple_actions = queries
        .iter()
        .map(|q| &q.action)
        .collect::<std::collections::HashSet<_>>()
        .len()
        > 1;
    let has_multiple_resource_types = queries
        .iter()
        .map(|q| &q.resource_type)
        .collect::<std::collections::HashSet<_>>()
        .len()
        > 1;
    let has_multiple_resource_ids = queries
        .iter()
        .map(|q| &q.resource_id)
        .collect::<std::collections::HashSet<_>>()
        .len()
        > 1;

    // Determine which attribute keys vary across queries
    let varying_attr_keys: std::collections::HashSet<String> = if queries.is_empty() {
        std::collections::HashSet::new()
    } else {
        // Collect all attribute keys
        let all_keys: std::collections::HashSet<String> = queries
            .iter()
            .flat_map(|q| q.attrs.iter().map(|(k, _)| k.clone()))
            .collect();

        // For each key, check if values vary
        all_keys
            .into_iter()
            .filter(|key| {
                let values: std::collections::HashSet<String> = queries
                    .iter()
                    .filter_map(|q| {
                        q.attrs
                            .iter()
                            .find(|(k, _)| k == key)
                            .map(|(_, v)| v.clone())
                    })
                    .collect();
                values.len() > 1
            })
            .collect()
    };

    // Generate IDs based only on varying fields
    for (index, query) in queries.iter_mut().enumerate() {
        let mut id_parts = Vec::new();

        if has_multiple_principals {
            // Extract meaningful parts from principal
            if let Some(entity_type) = query.principal.split("::").nth(1) {
                if let Some(entity_id) = query.principal.split("::").last() {
                    id_parts.push(format!("{}:{}", entity_type, entity_id));
                }
            } else {
                // Simple principal without namespace
                id_parts.push(query.principal.clone());
            }
        }

        if has_multiple_actions {
            // Extract action name (last part after ::)
            if let Some(action_name) = query.action.split("::").last() {
                id_parts.push(action_name.to_string());
            } else {
                id_parts.push(query.action.clone());
            }
        }

        if has_multiple_resource_types {
            id_parts.push(query.resource_type.clone());
        }

        if has_multiple_resource_ids {
            id_parts.push(query.resource_id.clone());
        }

        // Include only attributes that vary
        for (key, val) in &query.attrs {
            if varying_attr_keys.contains(key) {
                id_parts.push(format!("{}={}", key, val));
            }
        }

        // If nothing varies (single query), use descriptive format
        let query_id = if id_parts.is_empty() {
            format!("query-{}", index)
        } else {
            id_parts.join("|")
        };

        query.query_id = query_id;
    }
}

/// Generates all query permutations from matrix-expanded input
pub fn expand_matrix(
    principal: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    attrs: Vec<(String, String)>,
) -> Vec<MatrixQuery> {
    // Parse each field for alternatives
    let principals = parse_alternatives(principal);
    let actions = parse_alternatives(action);
    let resource_types = parse_alternatives(resource_type);
    let resource_ids = parse_alternatives(resource_id);

    // If no attributes, use single empty permutation
    let attr_permutations: Vec<Vec<(String, String)>> = if attrs.is_empty() {
        vec![vec![]]
    } else {
        // Parse each attribute value for alternatives
        let mut perms: Vec<Vec<(String, String)>> = vec![vec![]];

        for (key, value) in attrs {
            let value_alts = parse_alternatives(&value);
            let mut new_perms = Vec::new();

            for value_alt in value_alts {
                for perm in &perms {
                    let mut new_perm = perm.clone();
                    new_perm.push((key.clone(), value_alt.clone()));
                    new_perms.push(new_perm);
                }
            }

            perms = new_perms;
        }
        perms
    };

    // Generate cartesian product
    let mut queries = Vec::new();

    for action in &actions {
        for principal in &principals {
            for resource_type in &resource_types {
                for resource_id in &resource_ids {
                    for attr_perm in &attr_permutations {
                        queries.push(MatrixQuery {
                            principal: principal.clone(),
                            action: action.clone(),
                            resource_type: resource_type.clone(),
                            resource_id: resource_id.clone(),
                            attrs: attr_perm.clone(),
                            query_id: String::new(), // Temporary, will be set below
                        });
                    }
                }
            }
        }
    }

    // Generate smart IDs based on which fields actually vary
    generate_smart_query_ids(&mut queries);

    queries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_alternatives() {
        let alts = parse_alternatives("alice|bob");
        assert_eq!(alts, vec!["alice", "bob"]);
    }

    #[test]
    fn test_bracket_expansion() {
        let alts = parse_alternatives("alice[admins|webmasters]");
        assert_eq!(alts, vec!["alice[admins]", "alice[webmasters]"]);
    }

    #[test]
    fn test_bracket_with_commas() {
        let alts = parse_alternatives("alice[admins|webmasters,users]");
        assert_eq!(alts, vec!["alice[admins]", "alice[webmasters,users]"]);
    }

    #[test]
    fn test_no_expansion() {
        let alts = parse_alternatives("alice");
        assert_eq!(alts, vec!["alice"]);
    }

    #[test]
    fn test_multiple_principals() {
        let queries = expand_matrix("alice|bob", "Read", "Document", "doc1", vec![]);
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].principal, "alice");
        assert_eq!(queries[1].principal, "bob");
    }

    #[test]
    fn test_cartesian_product() {
        let queries = expand_matrix("alice|bob", "Read|Write", "Document", "doc1", vec![]);
        assert_eq!(queries.len(), 4); // 2 principals × 2 actions
        assert_eq!(queries[0].principal, "alice");
        assert_eq!(queries[0].action, "Read");
        assert_eq!(queries[1].principal, "bob");
        assert_eq!(queries[1].action, "Read");
        assert_eq!(queries[2].principal, "alice");
        assert_eq!(queries[2].action, "Write");
        assert_eq!(queries[3].principal, "bob");
        assert_eq!(queries[3].action, "Write");
    }
}
