//! Detector: Front-running susceptibility.
//!
//! Flags approval race conditions, missing slippage protection on swaps/withdraws,
//! front-runnable auctions without commit-reveal, unprotected first-come mints,
//! and MEV-attractive liquidation incentives.

use crate::helpers::{extract_function_name, get_function_visibility};
use crate::types::{Confidence, Finding, Severity};

pub fn detect_front_running(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_front_running_patterns(&root_node, source, findings);
}

fn find_front_running_patterns(
    node: &tree_sitter::Node,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];
        let func_name = extract_function_name(func_text);
        let visibility = get_function_visibility(func_text);

        if !visibility.is_externally_callable() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                find_front_running_patterns(&child, source, findings);
            }
            return;
        }

        // Pattern 1: Token approval without allowance check
        if func_name.contains("approve") {
            // Check if it's using standard approve without protection
            // Look for actual code patterns, not comments
            let has_allowance_check = (func_text.contains("allowance(")
                && (func_text.contains("== 0") || func_text.contains("require(")))
                || func_text.contains("allowance[")
                || func_text.contains("allowances[");
            let uses_safe_approve =
                func_text.contains("increaseAllowance") || func_text.contains("decreaseAllowance");

            // Only flag if it's a direct approve call (not wrapped in safe approve)
            let is_direct_approve =
                func_text.contains("approve(") || func_text.contains("super.approve");

            if is_direct_approve && !has_allowance_check && !uses_safe_approve {
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Approval Race Condition".to_string(),
                    message: "ERC20 approve vulnerable to front-running".to_string(),
                    suggestion:
                        "Use increaseAllowance/decreaseAllowance or require current allowance is 0"
                            .to_string(),
                    file: None,
                });
            }
        }

        // Pattern 2: Swap/Withdraw without slippage protection
        // Check swap/exchange functions
        if func_name.contains("swap") || func_name.contains("exchange") {
            let has_slippage = func_text.contains("minAmount")
                || func_text.contains("minOut")
                || func_text.contains("amountOutMin")
                || func_text.contains("slippage")
                || func_text.contains("deadline");

            if !has_slippage {
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::High,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Missing Slippage Protection".to_string(),
                    message: "Swap function without minimum output amount".to_string(),
                    suggestion:
                        "Add minAmountOut parameter and deadline for sandwich attack protection"
                            .to_string(),
                    file: None,
                });
            }
        }

        // Check withdraw functions that use price calculations (vulnerable to manipulation)
        if func_name.contains("withdraw")
            && (func_text.contains("getPrice")
                || func_text.contains("price")
                || func_text.contains("calculateShares")
                || func_text.contains("reserve"))
        {
            let has_slippage = func_text.contains("minAmount")
                || func_text.contains("minOut")
                || func_text.contains("amountOutMin")
                || func_text.contains("slippage")
                || func_text.contains("deadline")
                || func_text.contains("maxSlippage");

            if !has_slippage {
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::High,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Missing Slippage Protection".to_string(),
                    message:
                        "Withdraw function using price calculations without slippage protection"
                            .to_string(),
                    suggestion:
                        "Add minAmountOut parameter and deadline for sandwich attack protection"
                            .to_string(),
                    file: None,
                });
            }
        }

        // Pattern 3: Auction/bid without commit-reveal
        if func_name.contains("bid") || func_name.contains("auction") {
            let has_commit_reveal = func_text.contains("commit")
                || func_text.contains("reveal")
                || func_text.contains("hash");

            if !has_commit_reveal && func_text.contains("msg.value") {
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Front-Runnable Auction".to_string(),
                    message: "Auction bid visible in mempool before execution".to_string(),
                    suggestion: "Implement commit-reveal scheme for blind bidding".to_string(),
                    file: None,
                });
            }
        }

        // Pattern 4: First-come-first-serve without protection
        if func_name.contains("claim") || func_name.contains("mint") {
            let has_merkle = func_text.contains("merkle")
                || func_text.contains("Merkle")
                || func_text.contains("proof");
            let has_signature = func_text.contains("signature")
                || func_text.contains("ecrecover")
                || func_text.contains("ECDSA");
            let has_whitelist = func_text.contains("whitelist") || func_text.contains("allowlist");

            if !has_merkle && !has_signature && !has_whitelist {
                // Check if it's a limited mint
                if func_text.contains("maxSupply") || func_text.contains("limit") {
                    findings.push(Finding {
                        severity: Severity::Low,
                        confidence: Confidence::Low,
                        line: node.start_position().row + 1,
                        vulnerability_type: "Front-Runnable Mint".to_string(),
                        message: "First-come-first-serve mint vulnerable to front-running"
                            .to_string(),
                        suggestion: "Consider merkle proof whitelist or signature-based minting"
                            .to_string(),
                        file: None,
                    });
                }
            }
        }

        // Pattern 5: Liquidation without keeper incentive alignment
        if func_name.contains("liquidat") {
            let has_incentive = func_text.contains("bonus")
                || func_text.contains("reward")
                || func_text.contains("incentive")
                || func_text.contains("discount");

            if has_incentive {
                findings.push(Finding {
                    severity: Severity::Low,
                    confidence: Confidence::Low,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Liquidation MEV".to_string(),
                    message: "Liquidation with bonus is attractive to MEV searchers".to_string(),
                    suggestion: "Consider using Flashbots Protect or MEV-aware design".to_string(),
                    file: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_front_running_patterns(&child, source, findings);
    }
}
