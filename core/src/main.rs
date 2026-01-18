// ============================================================================
// Stealth - Smart Contract Security Scanner
// Version 0.4.0 - With Self-Service & Visibility Heuristics
// ============================================================================

use clap::{Parser, Subcommand};
use colored::*;
use serde::Serialize;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

// ============================================================================
// CLI STRUCTURE
// ============================================================================

#[derive(Parser)]
#[command(name = "stealth")]
#[command(about = "Smart contract security scanner for Solidity", long_about = None)]
#[command(version = "0.4.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan Solidity files for vulnerabilities
    Scan {
        /// File or directory to scan
        path: String,

        /// Output format (terminal, json)
        #[arg(short, long, default_value = "terminal")]
        format: String,

        /// Recursively scan directories
        #[arg(short, long)]
        recursive: bool,
    },
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    fn as_colored_str(&self) -> ColoredString {
        match self {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".blue(),
        }
    }

    #[allow(dead_code)]
    fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "High",
            Confidence::Medium => "Medium",
            Confidence::Low => "Low",
        }
    }
}

// ============================================================================
// FUNCTION VISIBILITY
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Visibility {
    Public,
    External,
    Internal,
    Private,
}

impl Visibility {
    /// Risk level for reentrancy (higher = more risky)
    #[allow(dead_code)]
    pub fn risk_level(&self) -> u8 {
        match self {
            Visibility::External => 3,
            Visibility::Public => 3,
            Visibility::Internal => 1,
            Visibility::Private => 0,
        }
    }

    pub fn is_externally_callable(&self) -> bool {
        matches!(self, Visibility::Public | Visibility::External)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::External => "external",
            Visibility::Internal => "internal",
            Visibility::Private => "private",
        }
    }
}

// ============================================================================
// FINDING STRUCTURE
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub confidence: Confidence,
    pub line: usize,
    pub vulnerability_type: String,
    pub message: String,
    pub suggestion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

impl Finding {
    fn print(&self) {
        println!(
            "[{}] {} at line {} (Confidence: {})",
            self.severity.as_colored_str(),
            self.vulnerability_type.bold(),
            self.line,
            self.confidence.as_str().dimmed()
        );
        println!("  {} {}", "→".cyan(), self.message);
        println!("  {} {}", "Fix:".green().bold(), self.suggestion);
        println!();
    }
}

#[derive(Default, Serialize)]
struct Statistics {
    critical: u32,
    high: u32,
    medium: u32,
    low: u32,
    confidence_high: u32,
    confidence_medium: u32,
    confidence_low: u32,
}

// ============================================================================
// SELF-SERVICE PATTERN DETECTION HELPERS
// ============================================================================

/// Check if a function name indicates a self-service pattern
fn is_self_service_function_name(func_name: &str) -> bool {
    let lower_name = func_name.to_lowercase();

    let self_service_names = [
        "deposit",
        "withdraw",
        "withdrawall",
        "withdrawto",
        "claim",
        "claimreward",
        "claimrewards",
        "claimall",
        "stake",
        "unstake",
        "restake",
        "transfer",
        "approve",
        "transferfrom",
        "mint",
        "burn",
        "redeem",
        "redeemall",
        "exit",
        "leave",
        "emergencywithdraw",
        "harvest",
        "compound",
        "reinvest",
    ];

    self_service_names
        .iter()
        .any(|&name| lower_name.contains(name))
}

/// Check if a function operates only on msg.sender's data
fn is_self_service_pattern(func_text: &str) -> bool {
    // Pattern 1: Operations on msg.sender's mappings
    let has_sender_mapping = func_text.contains("balances[msg.sender]")
        || func_text.contains("_balances[msg.sender]")
        || func_text.contains("deposits[msg.sender]")
        || func_text.contains("stakes[msg.sender]")
        || func_text.contains("rewards[msg.sender]")
        || func_text.contains("userInfo[msg.sender]");

    // Pattern 2: Transfer to msg.sender
    let transfer_to_sender = func_text.contains("payable(msg.sender)")
        || func_text.contains("msg.sender.call{value")
        || func_text.contains("(msg.sender).transfer(")
        || func_text.contains("safeTransfer(msg.sender");

    // Pattern 3: Token transfer to msg.sender
    let token_to_sender = func_text.contains("transfer(msg.sender,")
        || func_text.contains("_transfer(address(this), msg.sender");

    // Pattern 4: No arbitrary address parameter for fund destination
    let has_arbitrary_recipient = func_text.contains("address to,")
        || func_text.contains("address _to,")
        || func_text.contains("address recipient,")
        || func_text.contains("address _recipient,");

    // It's self-service if it operates on sender's data AND doesn't allow arbitrary recipients
    (has_sender_mapping || transfer_to_sender || token_to_sender) && !has_arbitrary_recipient
}

/// Combined check for self-service pattern (name + body analysis)
fn should_skip_access_control_warning(func_name: &str, func_text: &str) -> bool {
    is_self_service_function_name(func_name) && is_self_service_pattern(func_text)
}

// ============================================================================
// FUNCTION VISIBILITY HELPERS
// ============================================================================

/// Extract function visibility from function text
fn get_function_visibility(func_text: &str) -> Visibility {
    // Look at the signature portion (before the {)
    let signature_end = func_text.find('{').unwrap_or(func_text.len());
    let signature = &func_text[..signature_end];

    if signature.contains(" private")
        || signature.contains("\tprivate")
        || signature.contains("(private")
    {
        Visibility::Private
    } else if signature.contains(" internal")
        || signature.contains("\tinternal")
        || signature.contains("(internal")
    {
        Visibility::Internal
    } else if signature.contains(" external")
        || signature.contains("\texternal")
        || signature.contains("(external")
    {
        Visibility::External
    } else {
        Visibility::Public
    }
}

/// Get confidence level based on visibility
/// Private/Internal functions are less risky for reentrancy
fn visibility_adjusted_confidence(base: Confidence, visibility: Visibility) -> Confidence {
    match (base, visibility) {
        // Downgrade confidence for internal/private functions
        (Confidence::High, Visibility::Private) => Confidence::Low,
        (Confidence::High, Visibility::Internal) => Confidence::Medium,
        (Confidence::Medium, Visibility::Private) => Confidence::Low,
        // Keep base confidence otherwise
        _ => base,
    }
}

// ============================================================================
// GENERAL HELPER FUNCTIONS
// ============================================================================

/// Extract function name from function text
fn extract_function_name(func_text: &str) -> String {
    // Look for "function name(" pattern
    if let Some(start) = func_text.find("function ") {
        let after_function = &func_text[start + 9..];
        if let Some(end) = after_function.find('(') {
            return after_function[..end].trim().to_string();
        }
    }
    String::new()
}

/// Check if function has a modifier
fn has_modifier(func_text: &str, modifiers: &[&str]) -> bool {
    modifiers.iter().any(|m| func_text.contains(m))
}

/// Check for reentrancy guard modifiers
fn has_reentrancy_guard(func_text: &str) -> bool {
    has_modifier(
        func_text,
        &["nonReentrant", "noReentrant", "reentrancyGuard", "lock"],
    )
}

/// Check if function has access control
fn has_access_control(func_text: &str) -> bool {
    // Check modifiers
    let has_modifier = func_text.contains("onlyOwner")
        || func_text.contains("onlyAdmin")
        || func_text.contains("onlyRole")
        || func_text.contains("onlyAuthorized");

    // Check require statements with msg.sender
    let has_require_sender = func_text.contains("require")
        && (func_text.contains("msg.sender == owner")
            || func_text.contains("msg.sender == admin")
            || func_text.contains("_owner"));

    has_modifier || has_require_sender
}

// ============================================================================
// DETECTOR: REENTRANCY
// ============================================================================

fn detect_reentrancy(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
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

// ============================================================================
// DETECTOR: UNCHECKED EXTERNAL CALLS
// ============================================================================

fn detect_unchecked_calls(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
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

// ============================================================================
// DETECTOR: TX.ORIGIN AUTHENTICATION
// ============================================================================

fn detect_tx_origin(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
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

// ============================================================================
// DETECTOR: ACCESS CONTROL
// ============================================================================

fn detect_access_control(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_access_control_issues(&root_node, source, findings);
}

fn find_access_control_issues(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
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

// ============================================================================
// DETECTOR: DANGEROUS DELEGATECALL
// ============================================================================

fn detect_dangerous_delegatecall(
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

// ============================================================================
// DETECTOR: TIMESTAMP DEPENDENCE
// ============================================================================

fn detect_timestamp_dependence(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_timestamp_issues(&root_node, source, findings);
}

fn find_timestamp_issues(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];

        // Check for timestamp usage
        if func_text.contains("block.timestamp") || func_text.contains("now") {
            // Check for dangerous patterns
            let has_equality = func_text.contains("== block.timestamp")
                || func_text.contains("block.timestamp ==");
            let has_modulo =
                func_text.contains("% block.timestamp") || func_text.contains("block.timestamp %");

            // Lower severity for view/pure functions
            let is_view = func_text.contains(" view ") || func_text.contains(" pure ");

            if has_equality || has_modulo {
                findings.push(Finding {
                    severity: if has_modulo {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    confidence: if is_view {
                        Confidence::Low
                    } else {
                        Confidence::Medium
                    },
                    line: node.start_position().row + 1,
                    vulnerability_type: "Timestamp Dependence".to_string(),
                    message: if has_modulo {
                        "Using block.timestamp with modulo can be manipulated by miners".to_string()
                    } else {
                        "Exact comparison with block.timestamp can be manipulated".to_string()
                    },
                    suggestion:
                        "Use block.timestamp only for >15 minute precision; avoid equality checks"
                            .to_string(),
                    file: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_timestamp_issues(&child, source, findings);
    }
}

// ============================================================================
// DETECTOR: UNSAFE RANDOMNESS
// ============================================================================

fn detect_unsafe_random(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_random_issues(&root_node, source, findings);
}

fn find_random_issues(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    // Only check at function level to avoid duplicate reports from nested nodes
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];

        // Check for common bad randomness patterns
        let bad_patterns = [
            "keccak256(abi.encodePacked(block.timestamp",
            "keccak256(abi.encodePacked(block.difficulty",
            "keccak256(abi.encodePacked(block.number",
            "blockhash(",
        ];

        for pattern in bad_patterns {
            if func_text.contains(pattern) {
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Unsafe Randomness".to_string(),
                    message: "Using block variables for randomness can be predicted/manipulated"
                        .to_string(),
                    suggestion: "Use Chainlink VRF or commit-reveal scheme for secure randomness"
                        .to_string(),
                    file: None,
                });
                return; // One report per function is enough
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_random_issues(&child, source, findings);
    }
}

// ============================================================================
// DETECTOR: INTEGER OVERFLOW/UNDERFLOW
// ============================================================================

fn detect_integer_overflow(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
    // Check Solidity version - 0.8+ has built-in overflow checks
    let has_safe_version = source.contains("pragma solidity ^0.8")
        || source.contains("pragma solidity >=0.8")
        || source.contains("pragma solidity 0.8");

    if has_safe_version {
        // Check for unchecked blocks which bypass safety
        find_unchecked_math(&tree.root_node(), source, findings);
    } else {
        // Pre-0.8: check for unsafe math operations
        find_unsafe_math(&tree.root_node(), source, findings);
    }
}

fn find_unchecked_math(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    let text = &source[node.start_byte()..node.end_byte()];

    if text.contains("unchecked {") || text.contains("unchecked{") {
        // Find arithmetic in unchecked blocks
        let has_arithmetic = text.contains(" + ")
            || text.contains(" - ")
            || text.contains(" * ")
            || text.contains("++")
            || text.contains("--");

        if has_arithmetic {
            findings.push(Finding {
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                line: node.start_position().row + 1,
                vulnerability_type: "Unchecked Arithmetic".to_string(),
                message: "Arithmetic in unchecked block bypasses overflow protection".to_string(),
                suggestion: "Ensure overflow/underflow is impossible or add manual checks"
                    .to_string(),
                file: None,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_unchecked_math(&child, source, findings);
    }
}

fn find_unsafe_math(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];

        // Check for SafeMath usage
        let uses_safemath = func_text.contains(".add(")
            || func_text.contains(".sub(")
            || func_text.contains(".mul(")
            || func_text.contains(".div(");

        if !uses_safemath {
            // Look for raw arithmetic on uint types
            let has_unsafe_add = func_text.contains(" += ")
                || (func_text.contains(" + ") && func_text.contains("uint"));
            let has_unsafe_sub = func_text.contains(" -= ")
                || (func_text.contains(" - ") && func_text.contains("uint"));
            let has_unsafe_mul = func_text.contains(" *= ")
                || (func_text.contains(" * ") && func_text.contains("uint"));

            if has_unsafe_add || has_unsafe_sub || has_unsafe_mul {
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Integer Overflow/Underflow".to_string(),
                    message: "Arithmetic operation without SafeMath in Solidity <0.8".to_string(),
                    suggestion: "Use SafeMath library or upgrade to Solidity >=0.8.0".to_string(),
                    file: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_unsafe_math(&child, source, findings);
    }
}

// ============================================================================
// DETECTOR: FLASH LOAN VULNERABILITY
// ============================================================================

fn detect_flash_loan_vulnerability(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_flash_loan_patterns(&root_node, source, findings);
}

fn find_flash_loan_patterns(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
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

// ============================================================================
// DETECTOR: STORAGE COLLISION (PROXY CONTRACTS)
// ============================================================================

fn detect_storage_collision(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();

    // Detect if this is a proxy contract
    let is_proxy = source.contains("delegatecall")
        || source.contains("Proxy")
        || source.contains("Upgradeable")
        || source.contains("implementation");

    if is_proxy {
        find_storage_issues(&root_node, source, findings);
    }
}

fn find_storage_issues(node: &tree_sitter::Node, source: &str, findings: &mut Vec<Finding>) {
    // Check for state variables at the contract level
    if node.kind() == "contract_declaration" || node.kind() == "contract_definition" {
        let contract_text = &source[node.start_byte()..node.end_byte()];

        // Pattern 1: State variables in proxy without storage gap
        let has_state_vars = contract_text.contains("uint256 ")
            || contract_text.contains("address ")
            || contract_text.contains("mapping(")
            || contract_text.contains("bool ");

        let has_storage_gap = contract_text.contains("__gap")
            || contract_text.contains("uint256[")
            || contract_text.contains("bytes32[");

        let is_upgradeable = contract_text.contains("Upgradeable")
            || contract_text.contains("UUPS")
            || contract_text.contains("Transparent");

        if has_state_vars && is_upgradeable && !has_storage_gap {
            findings.push(Finding {
                severity: Severity::High,
                confidence: Confidence::Medium,
                line: node.start_position().row + 1,
                vulnerability_type: "Missing Storage Gap".to_string(),
                message: "Upgradeable contract without storage gap for future variables"
                    .to_string(),
                suggestion: "Add uint256[50] private __gap; at the end of storage variables"
                    .to_string(),
                file: None,
            });
        }

        // Pattern 2: Initializer without initialized flag
        if contract_text.contains("initialize")
            && !contract_text.contains("initializer")
            && !contract_text.contains("_initialized")
        {
            findings.push(Finding {
                severity: Severity::Critical,
                confidence: Confidence::Medium,
                line: node.start_position().row + 1,
                vulnerability_type: "Unprotected Initializer".to_string(),
                message: "Initialize function without initializer modifier".to_string(),
                suggestion: "Use OpenZeppelin's Initializable and add initializer modifier"
                    .to_string(),
                file: None,
            });
        }

        // Pattern 3: Constructor in upgradeable contract
        if is_upgradeable && contract_text.contains("constructor") {
            let constructor_has_logic = !contract_text.contains("constructor()")
                || contract_text.contains("constructor(")
                    && !contract_text.contains("constructor() {");

            if constructor_has_logic {
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::High,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Constructor in Proxy".to_string(),
                    message:
                        "Upgradeable contract with constructor logic (won't execute for proxy)"
                            .to_string(),
                    suggestion: "Move constructor logic to initialize() function".to_string(),
                    file: None,
                });
            }
        }
    }

    // Pattern 4: Direct storage slot access without EIP-1967
    if node.kind() == "function_definition" {
        let func_text = &source[node.start_byte()..node.end_byte()];

        if func_text.contains("sstore") || func_text.contains("sload") {
            let uses_eip1967 = func_text.contains("0x360894") ||  // Implementation slot
                              func_text.contains("0xb53127") ||   // Admin slot
                              func_text.contains("0x7050c9"); // Rollback slot

            if !uses_eip1967 {
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    line: node.start_position().row + 1,
                    vulnerability_type: "Non-Standard Storage Slot".to_string(),
                    message: "Direct storage access without EIP-1967 standard slots".to_string(),
                    suggestion: "Use EIP-1967 standard slots for proxy storage".to_string(),
                    file: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_storage_issues(&child, source, findings);
    }
}

// ============================================================================
// DETECTOR: FRONT-RUNNING SUSCEPTIBILITY
// ============================================================================

fn detect_front_running(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
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

// ============================================================================
// DETECTOR: DOS VIA UNBOUNDED LOOPS
// ============================================================================

fn detect_dos_loops(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
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
                let has_storage_write = func_text.contains(" = ") || func_text.contains("delete ");

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

// ============================================================================
// DETECTOR: UNCHECKED ERC20 RETURN VALUES
// ============================================================================

fn detect_unchecked_erc20(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
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

// ============================================================================
// MAIN SCANNING LOGIC
// ============================================================================

fn scan_file(file_path: &str) -> Vec<Finding> {
    let source = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!(
                "{} Could not read '{}': {}",
                "Error:".red().bold(),
                file_path,
                e
            );
            return Vec::new();
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if let Err(e) = parser.set_language(&tree_sitter_solidity::LANGUAGE.into()) {
        eprintln!(
            "{} Failed to load Solidity grammar: {}",
            "Error:".red().bold(),
            e
        );
        return Vec::new();
    }

    let tree = match parser.parse(&source, None) {
        Some(tree) => tree,
        None => {
            eprintln!("{} Failed to parse '{}'", "Error:".red().bold(), file_path);
            return Vec::new();
        }
    };

    let mut findings = Vec::new();

    // Run all detectors
    detect_reentrancy(&tree, &source, &mut findings);
    detect_unchecked_calls(&tree, &source, &mut findings);
    detect_tx_origin(&tree, &source, &mut findings);
    detect_access_control(&tree, &source, &mut findings);
    detect_dangerous_delegatecall(&tree, &source, &mut findings);
    detect_timestamp_dependence(&tree, &source, &mut findings);
    detect_unsafe_random(&tree, &source, &mut findings);
    detect_integer_overflow(&tree, &source, &mut findings);
    detect_flash_loan_vulnerability(&tree, &source, &mut findings);
    detect_storage_collision(&tree, &source, &mut findings);
    detect_front_running(&tree, &source, &mut findings);
    detect_dos_loops(&tree, &source, &mut findings);
    detect_unchecked_erc20(&tree, &source, &mut findings);

    // Add file path to findings
    for finding in &mut findings {
        finding.file = Some(file_path.to_string());
    }

    findings
}

fn scan_directory(dir_path: &str, recursive: bool) -> Vec<Finding> {
    let mut all_findings = Vec::new();

    let walker = if recursive {
        WalkDir::new(dir_path)
    } else {
        WalkDir::new(dir_path).max_depth(1)
    };

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |e| e == "sol") {
            let file_findings = scan_file(path.to_str().unwrap_or_default());
            all_findings.extend(file_findings);
        }
    }

    all_findings
}

fn calculate_statistics(findings: &[Finding]) -> Statistics {
    let mut stats = Statistics::default();

    for finding in findings {
        match finding.severity {
            Severity::Critical => stats.critical += 1,
            Severity::High => stats.high += 1,
            Severity::Medium => stats.medium += 1,
            Severity::Low => stats.low += 1,
        }
        match finding.confidence {
            Confidence::High => stats.confidence_high += 1,
            Confidence::Medium => stats.confidence_medium += 1,
            Confidence::Low => stats.confidence_low += 1,
        }
    }

    stats
}

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

fn print_results(path: &str, findings: &[Finding], stats: &Statistics) {
    println!("\n{}", "═".repeat(60).dimmed());
    println!("{}", "Stealth Security Scan Results".bold().underline());
    println!("{}", "═".repeat(60).dimmed());
    println!("{} {}\n", "Scanning:".bold(), path);

    if findings.is_empty() {
        println!("{}", "✓ No vulnerabilities found!".green().bold());
    } else {
        println!(
            "{} {} vulnerabilities found:\n",
            "⚠".yellow(),
            findings.len()
        );

        for finding in findings {
            finding.print();
        }

        // Print summary
        println!("{}", "─".repeat(60).dimmed());
        println!("{}", "Summary".bold());
        if stats.critical > 0 {
            println!("  {} Critical: {}", "●".red(), stats.critical);
        }
        if stats.high > 0 {
            println!("  {} High: {}", "●".red(), stats.high);
        }
        if stats.medium > 0 {
            println!("  {} Medium: {}", "●".yellow(), stats.medium);
        }
        if stats.low > 0 {
            println!("  {} Low: {}", "●".blue(), stats.low);
        }
    }
    println!();
}

fn print_json(findings: &[Finding], stats: &Statistics) {
    #[derive(Serialize)]
    struct Output<'a> {
        findings: &'a [Finding],
        statistics: &'a Statistics,
    }

    let output = Output {
        findings,
        statistics: stats,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            recursive,
        } => {
            let findings = if Path::new(&path).is_dir() {
                scan_directory(&path, recursive)
            } else {
                scan_file(&path)
            };

            let stats = calculate_statistics(&findings);

            match format.as_str() {
                "json" => print_json(&findings, &stats),
                _ => print_results(&path, &findings, &stats),
            }

            // Exit with code based on findings
            let exit_code = if stats.critical > 0 || stats.high > 0 {
                2
            } else if stats.medium > 0 {
                1
            } else {
                0
            };

            std::process::exit(exit_code);
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_service_function_names() {
        assert!(is_self_service_function_name("withdraw"));
        assert!(is_self_service_function_name("withdrawAll"));
        assert!(is_self_service_function_name("claim"));
        assert!(is_self_service_function_name("claimRewards"));
        assert!(is_self_service_function_name("stake"));
        assert!(is_self_service_function_name("deposit"));

        assert!(!is_self_service_function_name("setOwner"));
        assert!(!is_self_service_function_name("pause"));
        assert!(!is_self_service_function_name("initialize"));
    }

    #[test]
    fn test_self_service_pattern() {
        let safe_withdraw = r#"
            function withdraw() public {
                uint256 amt = balances[msg.sender];
                balances[msg.sender] = 0;
                payable(msg.sender).transfer(amt);
            }
        "#;
        assert!(is_self_service_pattern(safe_withdraw));

        let unsafe_withdraw = r#"
            function withdraw(address to, uint256 amount) public {
                balances[to] -= amount;
                payable(to).transfer(amount);
            }
        "#;
        assert!(!is_self_service_pattern(unsafe_withdraw));
    }

    #[test]
    fn test_visibility_detection() {
        assert_eq!(
            get_function_visibility("function foo() public { }"),
            Visibility::Public
        );
        assert_eq!(
            get_function_visibility("function foo() external { }"),
            Visibility::External
        );
        assert_eq!(
            get_function_visibility("function foo() internal { }"),
            Visibility::Internal
        );
        assert_eq!(
            get_function_visibility("function foo() private { }"),
            Visibility::Private
        );
    }

    #[test]
    fn test_visibility_confidence_adjustment() {
        assert_eq!(
            visibility_adjusted_confidence(Confidence::High, Visibility::Public),
            Confidence::High
        );
        assert_eq!(
            visibility_adjusted_confidence(Confidence::High, Visibility::Private),
            Confidence::Low
        );
        assert_eq!(
            visibility_adjusted_confidence(Confidence::High, Visibility::Internal),
            Confidence::Medium
        );
    }
}
