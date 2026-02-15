//! Detector: Dangerous delegatecall.
//!
//! Flags `delegatecall` to user-supplied addresses without access control,
//! which allows arbitrary code execution in the calling contract's context.

use crate::helpers::has_access_control;
use crate::types::{Confidence, Finding, Severity};

pub fn detect_dangerous_delegatecall(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_delegatecall_issues(&root_node, source, findings);
}

fn find_delegatecall_issues(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];

        if func_text.contains(".delegatecall(") {
            // Check if target is from parameter
            let has_address_param = func_text.contains("address ")
                && (func_text.contains("(address ") || func_text.contains(", address "));

            if has_address_param && !has_access_control(func_text) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Dangerous Delegatecall".to_string(),
                    message: "Delegatecall to user-supplied address without access control"
                        .to_string(),
                    suggestion:
                        "Add strict access control or use a whitelist for delegatecall targets"
                            .to_string(),
                    file: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_delegatecall_issues(&child, source, findings);
    }
}
