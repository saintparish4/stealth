//! Detector: tx.origin authentication.
//!
//! Flags comparisons against `tx.origin` which are vulnerable to phishing attacks.

use crate::types::{Confidence, Finding, Severity};

pub fn detect_tx_origin(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_tx_origin(&root_node, source, findings);
}

fn find_tx_origin(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    let text = &source[node.start_byte()..node.end_byte()];

    // Only check binary_expression to avoid duplicate reports from nested nodes
    // (require() contains binary_expression, so we'd report twice)
    if node.kind() == "binary_expression" && text.contains("tx.origin") {
        // Check if it's used for authorization (comparison)
        if text.contains("==") || text.contains("!=") {
            findings.push(Finding {
                severity: Severity::High,
                confidence: Confidence::High,
                line: node.start_position().row + 1,
                vulnerability_type: "tx.origin Authentication".to_string(),
                message: "Using tx.origin for authorization is vulnerable to phishing attacks"
                    .to_string(),
                suggestion: "Use msg.sender instead of tx.origin for authentication checks"
                    .to_string(),
                file: None,
            });
            return; // Don't recurse into children - we found it
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_tx_origin(&child, source, findings);
    }
}
