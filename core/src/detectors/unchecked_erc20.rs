//! Detector: Unchecked ERC-20 return values.
//!
//! Flags `transfer()`, `transferFrom()`, and `approve()` calls whose boolean
//! return value is silently discarded. Non-reverting tokens (USDT, BNB, etc.)
//! will succeed at the EVM level but return `false`, leading to silent fund loss.

use crate::types::{Confidence, Finding, Severity};

pub fn detect_unchecked_erc20(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
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
                        id: String::new(),
                        detector_id: "unchecked-erc20".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        line,
                        vulnerability_type: "Unchecked ERC20 Transfer".to_string(),
                        message: "ERC20 transfer() return value not checked".to_string(),
                        suggestion: "Use SafeERC20.safeTransfer() or check return value"
                            .to_string(),
                        remediation: None,
                        owasp_category: Some("SC04:2025 - Lack of Input Validation".to_string()),
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
                    id: String::new(),
                    detector_id: "unchecked-erc20".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    line,
                    vulnerability_type: "Unchecked ERC20 TransferFrom".to_string(),
                    message: "ERC20 transferFrom() return value not checked".to_string(),
                    suggestion: "Use SafeERC20.safeTransferFrom() or check return value"
                        .to_string(),
                    remediation: None,
                    owasp_category: Some("SC04:2025 - Lack of Input Validation".to_string()),
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
                    id: String::new(),
                    detector_id: "unchecked-erc20".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    line,
                    vulnerability_type: "Unchecked ERC20 Approve".to_string(),
                    message: "ERC20 approve() return value not checked".to_string(),
                    suggestion: "Use SafeERC20.safeApprove() or forceApprove()".to_string(),
                    remediation: None,
                    owasp_category: Some("SC04:2025 - Lack of Input Validation".to_string()),
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
