//! Detector: Flash loan vulnerability patterns.
//!
//! Flags spot-price calculations without TWAP/Chainlink, single-transaction
//! balance checks in sensitive functions, and unvalidated flash-loan callbacks.

use crate::helpers::extract_function_name;
use crate::types::{Confidence, Finding, Severity};

pub fn detect_flash_loan_vulnerability(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_flash_loan_patterns(&root_node, source, findings);
}

fn find_flash_loan_patterns(
    node: &tree_sitter::Node,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];
        let func_name = extract_function_name(func_text);

        // Pattern 1: Price oracle manipulation vulnerability
        let uses_spot_price = func_text.contains("getReserves")
            || func_text.contains("balanceOf(address(this))")
            || func_text.contains("token.balanceOf")
            || func_text.contains("pair.getReserves");

        let calculates_price = func_text.contains("price")
            || func_text.contains("rate")
            || func_text.contains("ratio");

        let no_twap = !func_text.contains("TWAP")
            && !func_text.contains("twap")
            && !func_text.contains("oracle")
            && !func_text.contains("Chainlink");

        if uses_spot_price && calculates_price && no_twap {
            findings.push(Finding {
                severity: Severity::High,
                confidence: Confidence::Medium,
                line: node.start_position().row + 1,
                vulnerability_type: "Flash Loan Price Manipulation".to_string(),
                message: "Spot price calculation vulnerable to flash loan manipulation".to_string(),
                suggestion: "Use TWAP oracle or Chainlink price feeds instead of spot prices"
                    .to_string(),
                file: None,
            });
        }

        // Pattern 2: Single-transaction balance checks
        let has_balance_check = func_text.contains("balanceOf")
            && (func_text.contains("require") || func_text.contains("if"));
        let modifies_state = func_text.contains(" = ")
            || func_text.contains("transfer")
            || func_text.contains("mint");

        if has_balance_check && modifies_state && !func_text.contains("flashLoan") {
            // Check if it's a sensitive function
            let is_sensitive = func_name.contains("swap")
                || func_name.contains("borrow")
                || func_name.contains("liquidat")
                || func_name.contains("withdraw");

            if is_sensitive {
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Flash Loan Susceptible".to_string(),
                    message: format!(
                        "Function '{}' uses balance checks that could be manipulated",
                        func_name
                    ),
                    suggestion: "Consider adding flash loan guards or using time-weighted values"
                        .to_string(),
                    file: None,
                });
            }
        }

        // Pattern 3: Callback without validation
        if func_text.contains("Callback") || func_text.contains("callback") {
            let validates_caller =
                func_text.contains("msg.sender ==") || func_text.contains("require(msg.sender");

            if !validates_caller {
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::High,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Unvalidated Callback".to_string(),
                    message: "Flash loan callback without caller validation".to_string(),
                    suggestion: "Validate msg.sender is the expected flash loan provider"
                        .to_string(),
                    file: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_flash_loan_patterns(&child, source, findings);
    }
}
