//! Detector: Denial-of-service via unbounded loops.
//!
//! Flags unbounded iteration over dynamic arrays, external calls inside loops,
//! growing arrays without cleanup, and expensive delete operations in loops.

use crate::helpers::{extract_function_name, get_function_visibility};
use crate::types::{Confidence, Finding, Severity};

pub fn detect_dos_loops(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_dos_patterns(&root_node, source, findings);
}

fn find_dos_patterns(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];
        let func_name = extract_function_name(func_text);
        let visibility = get_function_visibility(func_text);

        // Only check externally callable functions
        if !visibility.is_externally_callable() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                find_dos_patterns(&child, source, findings);
            }
            return;
        }

        // Pattern 1: Loop over dynamic array
        let has_for_loop = func_text.contains("for (") || func_text.contains("for(");
        let has_while_loop = func_text.contains("while (") || func_text.contains("while(");

        if has_for_loop || has_while_loop {
            // Check for unbounded iteration
            let iterates_array = func_text.contains(".length")
                || func_text.contains("< users")
                || func_text.contains("< holders")
                || func_text.contains("< recipients")
                || func_text.contains("beneficiaries.length")
                || func_text.contains("addresses.length")
                || func_text.contains("whitelistedAddresses.length");

            let has_bound = func_text.contains("maxIterations")
                || func_text.contains("batchSize")
                || func_text.contains("limit")
                || func_text.contains("MAX_");

            if iterates_array && !has_bound {
                // Check if it does expensive operations
                let has_external_call = func_text.contains(".call")
                    || func_text.contains(".transfer")
                    || func_text.contains(".send");
                let has_storage_write =
                    func_text.contains(" = ") || func_text.contains("delete ");

                let severity = if has_external_call {
                    Severity::High
                } else if has_storage_write {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                findings.push(Finding {
                    severity,
                    confidence: Confidence::Medium,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Unbounded Loop".to_string(),
                    message: format!(
                        "Function '{}' has unbounded loop that may exceed gas limit",
                        func_name
                    ),
                    suggestion: "Add pagination or maximum iteration limit".to_string(),
                    file: None,
                });
            }
        }

        // Pattern 2: Push to array that's later iterated
        if func_text.contains(".push(") {
            // Check if any function iterates this array
            let array_patterns = [
                "users.push",
                "holders.push",
                "recipients.push",
                "addresses.push",
                "stakers.push",
                "members.push",
            ];

            for pattern in array_patterns {
                if func_text.contains(pattern) {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        confidence: Confidence::Low,
                        line: node.start_position().row + 1,
                        vulnerability_type: "Growing Array".to_string(),
                        message: "Array grows unbounded - iteration may exceed gas limit"
                            .to_string(),
                        suggestion: "Use mapping instead of array, or implement cleanup mechanism"
                            .to_string(),
                        file: None,
                    });
                    break;
                }
            }
        }

        // Pattern 3: External call in loop (including internal transfers)
        if (has_for_loop || has_while_loop)
            && (func_text.contains(".call")
                || func_text.contains(".transfer")
                || func_text.contains(".send")
                || func_text.contains("safeTransfer")
                || func_text.contains("_transfer("))
        // Internal ERC20 transfer
        {
            findings.push(Finding {
                severity: Severity::High,
                confidence: Confidence::High,
                line: node.start_position().row + 1,
                vulnerability_type: "External Call in Loop".to_string(),
                message: "External calls in loop - single failure can revert entire transaction"
                    .to_string(),
                suggestion:
                    "Use pull-over-push pattern: let users withdraw instead of pushing to them"
                        .to_string(),
                file: None,
            });
        }

        // Pattern 4: Delete from array in loop (expensive)
        if (has_for_loop || has_while_loop) && func_text.contains("delete ") {
            findings.push(Finding {
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                line: node.start_position().row + 1,
                vulnerability_type: "Expensive Loop Operation".to_string(),
                message: "Delete operations in loop are gas-expensive".to_string(),
                suggestion: "Consider swap-and-pop pattern or lazy deletion".to_string(),
                file: None,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_dos_patterns(&child, source, findings);
    }
}
