//! Detector: Unchecked ERC-20 return values.
//!
//! Flags `transfer()`, `transferFrom()`, and `approve()` calls whose boolean
//! return value is silently discarded. Non-reverting tokens (USDT, BNB, etc.)
//! will succeed at the EVM level but return `false`, leading to silent fund loss.

use crate::types::{Confidence, Finding, Severity};

pub fn detect_unchecked_erc20(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_unchecked_erc20(&root_node, source, findings);
}

fn find_unchecked_erc20(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "expression_statement" {
        let text = &source[node.start_byte()..node.end_byte()];
        let line = node.start_position().row + 1;

        // Pattern 1: Unchecked transfer
        if text.contains(".transfer(") && !text.contains("safeTransfer") {
            // Check if return value is used
            let trimmed = text.trim();
            if !trimmed.starts_with("require")
                && !trimmed.starts_with("bool")
                && !trimmed.starts_with("if")
                && !trimmed.contains("= ")
            {
                // Exclude ETH transfers (address.transfer)
                if !text.contains("payable(") {
                    findings.push(Finding {
                        severity: Severity::High,
                        confidence: Confidence::High,
                        line,
                        vulnerability_type: "Unchecked ERC20 Transfer".to_string(),
                        message: "ERC20 transfer() return value not checked".to_string(),
                        suggestion: "Use SafeERC20.safeTransfer() or check return value"
                            .to_string(),
                        file: None,
                    });
                }
            }
        }

        // Pattern 2: Unchecked transferFrom
        if text.contains(".transferFrom(") && !text.contains("safeTransferFrom") {
            let trimmed = text.trim();
            if !trimmed.starts_with("require")
                && !trimmed.starts_with("bool")
                && !trimmed.starts_with("if")
                && !trimmed.contains("= ")
            {
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::High,
                    line,
                    vulnerability_type: "Unchecked ERC20 TransferFrom".to_string(),
                    message: "ERC20 transferFrom() return value not checked".to_string(),
                    suggestion: "Use SafeERC20.safeTransferFrom() or check return value"
                        .to_string(),
                    file: None,
                });
            }
        }

        // Pattern 3: Unchecked approve
        if text.contains(".approve(") && !text.contains("safeApprove") {
            let trimmed = text.trim();
            if !trimmed.starts_with("require")
                && !trimmed.starts_with("bool")
                && !trimmed.starts_with("if")
                && !trimmed.contains("= ")
            {
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    line,
                    vulnerability_type: "Unchecked ERC20 Approve".to_string(),
                    message: "ERC20 approve() return value not checked".to_string(),
                    suggestion: "Use SafeERC20.safeApprove() or forceApprove()".to_string(),
                    file: None,
                });
            }
        }
    }

    // Also check at function level for patterns
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];

        // Check if using ERC20 without SafeERC20
        let uses_erc20 = func_text.contains("IERC20")
            || func_text.contains("ERC20")
            || func_text.contains("token.");
        let uses_safe_erc20 = func_text.contains("SafeERC20")
            || func_text.contains("safeTransfer")
            || func_text.contains("safeApprove");

        if uses_erc20 && !uses_safe_erc20 {
            // Check for direct calls without return check
            let has_unchecked = (func_text.contains(".transfer(")
                || func_text.contains(".transferFrom(")
                || func_text.contains(".approve("))
                && !func_text.contains("require(token.")
                && !func_text.contains("require(IERC20");

            if has_unchecked {
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Missing SafeERC20".to_string(),
                    message: "ERC20 operations without SafeERC20 wrapper".to_string(),
                    suggestion: "Import and use SafeERC20 for all token operations".to_string(),
                    file: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_unchecked_erc20(&child, source, findings);
    }
}
