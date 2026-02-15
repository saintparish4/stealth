//! Detector: Missing access control on sensitive functions.
//!
//! Flags public/external functions that perform sensitive operations (selfdestruct,
//! delegatecall, ownership changes, etc.) or allow arbitrary fund transfers without
//! access-control modifiers or `require(msg.sender == ...)` checks.

use crate::helpers::{
    extract_function_name, get_function_visibility, has_access_control,
    should_skip_access_control_warning,
};
use crate::types::{Confidence, Finding, Severity};

pub fn detect_access_control(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_access_control_issues(&root_node, source, findings);
}

fn find_access_control_issues(
    node: &tree_sitter::Node,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];
        let func_name = extract_function_name(func_text);
        let visibility = get_function_visibility(func_text);

        // Only check public/external functions
        if !visibility.is_externally_callable() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                find_access_control_issues(&child, source, findings);
            }
            return;
        }

        // Skip pure user functions - these are meant to be called by anyone
        // Note: transfer/transferFrom are checked separately for arbitrary recipients
        let pure_user_functions = [
            "stake",
            "unstake",
            "deposit",
            "claim",
            "claimReward",
            "claimRewards",
            "harvest",
            "compound",
            "reinvest",
            "exit",
            "leave",
            "balanceOf",
            "allowance",
            "totalSupply",
            "name",
            "symbol",
            "decimals",
            "getPrice",
            "getShares",
            "getBalance",
            "getReward",
            "earned",
            "getStakerInfo",
            "getContractStats",
            "getTotalReleasableAmount",
        ];

        let func_name_lower = func_name.to_lowercase();
        if pure_user_functions
            .iter()
            .any(|&name| func_name_lower == name.to_lowercase())
        {
            // This is a pure user function - skip access control check
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                find_access_control_issues(&child, source, findings);
            }
            return;
        }

        // Sensitive operations that usually need access control
        let sensitive_keywords = [
            "selfdestruct",
            "suicide",
            "delegatecall",
            "setOwner",
            "changeOwner",
            "transferOwnership",
            "setAdmin",
            "addAdmin",
            "pause",
            "unpause",
            "setFee",
            "setRate",
            "upgrade",
            "setImplementation",
            "initialize",
            "init",
        ];

        let is_sensitive = sensitive_keywords
            .iter()
            .any(|&kw| func_text.to_lowercase().contains(&kw.to_lowercase()));

        // Check for self-service pattern
        if is_sensitive && !has_access_control(func_text) {
            // Skip if this is a self-service function
            if should_skip_access_control_warning(&func_name, func_text) {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    find_access_control_issues(&child, source, findings);
                }
                return;
            }

            findings.push(Finding {
                severity: Severity::High,
                confidence: Confidence::High,
                line: node.start_position().row + 1,
                vulnerability_type: "Missing Access Control".to_string(),
                message: format!(
                    "Function '{}' performs sensitive operations without access control",
                    func_name
                ),
                suggestion: "Add onlyOwner, onlyAdmin, or similar access control modifier"
                    .to_string(),
                file: None,
            });
        }

        // Check for withdraw functions without access control
        let withdraw_keywords = ["withdraw", "transfer", "send"];
        let has_withdraw_action = withdraw_keywords
            .iter()
            .any(|&kw| func_name.to_lowercase().contains(kw));

        if has_withdraw_action {
            // Skip self-service withdrawals
            if should_skip_access_control_warning(&func_name, func_text) {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    find_access_control_issues(&child, source, findings);
                }
                return;
            }

            // Check if it allows arbitrary recipient
            let has_arbitrary_recipient = func_text.contains("address to")
                || func_text.contains("address _to")
                || func_text.contains("address recipient");

            if has_arbitrary_recipient && !has_access_control(func_text) {
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::High,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Unrestricted Fund Transfer".to_string(),
                    message: format!(
                        "Function '{}' allows arbitrary fund transfers without access control",
                        func_name
                    ),
                    suggestion: "Add access control or restrict to msg.sender withdrawals only"
                        .to_string(),
                    file: None,
                });
            }
        }
    }

    // Recurse
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_access_control_issues(&child, source, findings);
    }
}
