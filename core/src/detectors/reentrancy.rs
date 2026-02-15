//! Detector: Reentrancy vulnerabilities.
//!
//! Flags external calls (`.call`, `.transfer`, `.send`) followed by state changes
//! without a reentrancy guard modifier.

use crate::helpers::{
    get_function_visibility, has_reentrancy_guard, visibility_adjusted_confidence,
};
use crate::types::{Confidence, Finding, Severity};

pub fn detect_reentrancy(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_reentrancy(&root_node, source, findings);
}

fn find_reentrancy(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];

        // Skip if has reentrancy guard
        if has_reentrancy_guard(func_text) {
            return;
        }

        // Get visibility for confidence adjustment
        let visibility = get_function_visibility(func_text);

        // Track state changes and external calls
        let mut external_call_line: Option<usize> = None;
        let mut state_change_line: Option<usize> = None;
        let mut external_call_found = false;

        // Check for external calls
        let has_call = func_text.contains(".call{") || func_text.contains(".call(");
        let has_transfer = func_text.contains(".transfer(");
        let has_send = func_text.contains(".send(");

        if has_call || has_transfer || has_send {
            // Find the line of the external call
            for (i, line) in source[node.start_byte()..node.end_byte()]
                .lines()
                .enumerate()
            {
                let global_line = node.start_position().row + i + 1;
                if line.contains(".call{")
                    || line.contains(".call(")
                    || line.contains(".transfer(")
                    || line.contains(".send(")
                {
                    external_call_line = Some(global_line);
                    external_call_found = true;
                }
                // Look for state changes AFTER external call
                if external_call_found
                    && (line.contains(" = ") || line.contains(" += ") || line.contains(" -= "))
                    && !line.contains("bool ")
                    && !line.contains("uint")
                    && !line.contains("address ")
                {
                    state_change_line = Some(global_line);
                    break;
                }
            }
        }

        // Report if we found state change after external call
        if let (Some(call_line), Some(change_line)) = (external_call_line, state_change_line) {
            if change_line > call_line {
                // Adjust confidence based on visibility
                let base_confidence = Confidence::High;
                let adjusted_confidence =
                    visibility_adjusted_confidence(base_confidence, visibility);

                let visibility_note = if !visibility.is_externally_callable() {
                    format!(" ({} function - lower risk)", visibility.as_str())
                } else {
                    String::new()
                };

                findings.push(Finding {
                    severity: Severity::High,
                    confidence: adjusted_confidence,
                    line: call_line,
                    vulnerability_type: "Reentrancy".to_string(),
                    message: format!(
                        "External call at line {}, state change at line {}{}",
                        call_line, change_line, visibility_note
                    ),
                    suggestion:
                        "Move state changes before external call, or add nonReentrant modifier"
                            .to_string(),
                    file: None,
                });
            }
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_reentrancy(&child, source, findings);
    }
}
