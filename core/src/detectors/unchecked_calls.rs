//! Detector: Unchecked external call return values.
//!
//! Flags `.call{...}(...)` statements where the return value is not captured
//! or checked with `require`.

use crate::types::{Confidence, Finding, Severity};

pub fn detect_unchecked_calls(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_unchecked_calls(&root_node, source, findings);
}

fn find_unchecked_calls(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "expression_statement" {
        let text = &source[node.start_byte()..node.end_byte()];

        // Check for .call without capturing return value
        if text.contains(".call{") || text.contains(".call(") {
            // If the line doesn't start with assignment, it's unchecked
            let trimmed = text.trim();
            if !trimmed.starts_with("(bool")
                && !trimmed.starts_with("bool")
                && !trimmed.contains("= ")
            {
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Unchecked Call".to_string(),
                    message: "External call return value is not checked".to_string(),
                    suggestion: "Check the return value: (bool success, ) = addr.call(...); require(success);".to_string(),
                    file: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_unchecked_calls(&child, source, findings);
    }
}
