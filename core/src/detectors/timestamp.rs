//! Detector: Timestamp dependence.
//!
//! Flags exact equality checks and modulo operations on `block.timestamp`,
//! which can be manipulated by miners within a ~15-second window.

use crate::types::{Confidence, Finding, Severity};

pub fn detect_timestamp_dependence(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_timestamp_issues(&root_node, source, findings);
}

fn find_timestamp_issues(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];

        // Check for timestamp usage
        if func_text.contains("block.timestamp") || func_text.contains("now") {
            // Check for dangerous patterns
            let has_equality = func_text.contains("== block.timestamp")
                || func_text.contains("block.timestamp ==");
            let has_modulo =
                func_text.contains("% block.timestamp") || func_text.contains("block.timestamp %");

            // Lower severity for view/pure functions
            let is_view = func_text.contains(" view ") || func_text.contains(" pure ");

            if has_equality || has_modulo {
                findings.push(Finding {
                    severity: if has_modulo {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    confidence: if is_view {
                        Confidence::Low
                    } else {
                        Confidence::Medium
                    },
                    line: node.start_position().row + 1,
                    vulnerability_type: "Timestamp Dependence".to_string(),
                    message: if has_modulo {
                        "Using block.timestamp with modulo can be manipulated by miners".to_string()
                    } else {
                        "Exact comparison with block.timestamp can be manipulated".to_string()
                    },
                    suggestion:
                        "Use block.timestamp only for >15 minute precision; avoid equality checks"
                            .to_string(),
                    file: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_timestamp_issues(&child, source, findings);
    }
}
