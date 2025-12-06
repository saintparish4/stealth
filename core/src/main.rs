use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::process;

#[derive(Parser)]
#[command(name = "stealth")]
#[command(version = "0.1.0")]
#[command(about = "Smart contract security scanner for Solidity", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a Solidity file for vulnerabilities
    Scan {
        /// Path to the Solidity file to scan
        file: String,
    },
}

#[derive(Debug, Clone)]
enum Severity {
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
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    fn as_str(&self) -> &str {
        match self {
            Confidence::High => "High",
            Confidence::Medium => "Medium",
            Confidence::Low => "Low",
        }
    }
}

#[derive(Debug)]
struct Finding {
    severity: Severity,
    confidence: Confidence,
    line: usize,
    vulnerability_type: String,
    message: String,
    suggestion: String,
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { file } => {
            scan_file(&file);
        }
    }
}

fn scan_file(file_path: &str) {
    // Read the Solidity file
    let source_code = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!(
                "{} Could not read file '{}': {}",
                "Error:".red().bold(),
                file_path,
                e
            );
            process::exit(1);
        }
    };

    // Initialize parser with Solidity grammar
    let mut parser = tree_sitter::Parser::new();
    let language = unsafe {
        std::mem::transmute::<
            tree_sitter_language::LanguageFn,
            unsafe extern "C" fn() -> tree_sitter::Language,
        >(tree_sitter_solidity::LANGUAGE)()
    };
    if let Err(e) = parser.set_language(&language) {
        eprintln!(
            "{} Failed to load Solidity grammar: {}",
            "Error:".red().bold(),
            e
        );
        process::exit(1);
    }

    // Parse the source code
    let tree = match parser.parse(&source_code, None) {
        Some(tree) => tree,
        None => {
            eprintln!(
                "{} Failed to parse Solidity file. The syntax may be invalid.",
                "Error:".red().bold()
            );
            process::exit(1);
        }
    };

    // Run all detectors
    let mut findings = Vec::new();

    detect_reentrancy(&tree, &source_code, &mut findings);
    detect_unchecked_calls(&tree, &source_code, &mut findings);
    detect_tx_origin(&tree, &source_code, &mut findings);
    detect_access_control(&tree, &source_code, &mut findings);
    detect_dangerous_delegatecall(&tree, &source_code, &mut findings);
    detect_timestamp_dependence(&tree, &source_code, &mut findings);
    detect_unsafe_random(&tree, &source_code, &mut findings);

    // Display results
    println!("\n{}", "Vanguard Security Scan Results".bold().underline());
    println!("{} {}\n", "Scanning:".bold(), file_path);

    if findings.is_empty() {
        println!("{} No vulnerabilities detected.\n", "✓".green().bold());
    } else {
        let count_msg = if findings.len() == 1 {
            "1 vulnerability".to_string()
        } else {
            format!("{} vulnerabilities", findings.len())
        };
        println!("{} {} found:\n", "⚠".yellow().bold(), count_msg);

        for finding in findings {
            finding.print();
        }
    }
}

// Detector 1: Reentrancy
fn detect_reentrancy(tree: &tree_sitter::Tree, source_code: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_functions(&root_node, source_code, findings);
}

fn find_functions(node: &tree_sitter::Node, source_code: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "function_definition" {
        check_function_for_reentrancy(node, source_code, findings);
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_functions(&child, source_code, findings);
        }
    }
}

fn check_function_for_reentrancy(
    function_node: &tree_sitter::Node,
    source_code: &str,
    findings: &mut Vec<Finding>,
) {
    let body = match find_child_by_kind(function_node, "function_body") {
        Some(b) => b,
        None => return,
    };

    let statements = collect_statements(&body);

    for (i, stmt) in statements.iter().enumerate() {
        if is_external_call(stmt, source_code) {
            for later_stmt in statements.iter().skip(i + 1) {
                if is_state_change(later_stmt, source_code) {
                    let line = stmt.start_position().row + 1;
                    let state_line = later_stmt.start_position().row + 1;

                    // Determine confidence based on pattern clarity
                    let confidence = if is_balance_mapping_change(later_stmt, source_code) {
                        Confidence::High // Classic reentrancy pattern
                    } else {
                        Confidence::Medium // General state change
                    };

                    findings.push(Finding {
                        severity: Severity::High,
                        confidence,
                        line,
                        vulnerability_type: "Reentrancy".to_string(),
                        message: format!(
                            "External call at line {}, state change at line {}",
                            line, state_line
                        ),
                        suggestion:
                            "Move state changes before external call, or add nonReentrant modifier"
                                .to_string(),
                    });
                    return;
                }
            }
        }
    }
}

// Detector 2: Unchecked External Calls
fn detect_unchecked_calls(
    tree: &tree_sitter::Tree,
    source_code: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_unchecked_calls(&root_node, source_code, findings);
}

fn find_unchecked_calls(node: &tree_sitter::Node, source_code: &str, findings: &mut Vec<Finding>) {
    // Look for .call() without checking return value
    if node.kind() == "expression_statement" {
        let text = &source_code[node.byte_range()];

        // Check if this is a .call() without capturing return value
        if text.contains(".call(") || text.contains(".call{") {
            // If the statement doesn't start with a variable assignment or require/if check
            let trimmed = text.trim();
            if !trimmed.starts_with("(")
                && !trimmed.starts_with("require")
                && !trimmed.starts_with("if")
            {
                let line = node.start_position().row + 1;
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::High,  // Very clear pattern
                    line,
                    vulnerability_type: "Unchecked Call".to_string(),
                    message: "External call return value is not checked".to_string(),
                    suggestion: "Check the return value: (bool success, ) = addr.call(...); require(success, \"Call failed\");".to_string(),
                });
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_unchecked_calls(&child, source_code, findings);
        }
    }
}

// Detector 3: tx.origin for Authentication
fn detect_tx_origin(tree: &tree_sitter::Tree, source_code: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_tx_origin_usage(&root_node, source_code, findings);
}

fn find_tx_origin_usage(node: &tree_sitter::Node, source_code: &str, findings: &mut Vec<Finding>) {
    let text = &source_code[node.byte_range()];

    // Check for tx.origin in require statements or conditionals (potential auth check)
    if (node.kind() == "call_expression"
        || node.kind() == "require_statement"
        || node.kind() == "if_statement"
        || node.kind() == "binary_expression")
        && text.contains("tx.origin")
    {
        // Check if it's being used for comparison (authentication pattern)
        if text.contains("==") || text.contains("!=") {
            let line = node.start_position().row + 1;
            findings.push(Finding {
                severity: Severity::High,
                confidence: Confidence::High, // Definitive anti-pattern
                line,
                vulnerability_type: "tx.origin Authentication".to_string(),
                message: "Using tx.origin for authorization is unsafe".to_string(),
                suggestion: "Use msg.sender instead of tx.origin for authentication checks"
                    .to_string(),
            });
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_tx_origin_usage(&child, source_code, findings);
        }
    }
}

// Detector 4: Missing Access Control
fn detect_access_control(tree: &tree_sitter::Tree, source_code: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_missing_access_control(&root_node, source_code, findings);
}

fn find_missing_access_control(
    node: &tree_sitter::Node,
    source_code: &str,
    findings: &mut Vec<Finding>,
) {
    if node.kind() == "function_definition" {
        let func_text = &source_code[node.byte_range()];

        // Look for sensitive functions (withdraw, transfer, destroy, kill, etc.) without modifiers
        let sensitive_names = [
            "withdraw",
            "transfer",
            "destroy",
            "selfdestruct",
            "kill",
            "suicide",
        ];
        let has_sensitive_name = sensitive_names
            .iter()
            .any(|&name| func_text.to_lowercase().contains(name));

        if has_sensitive_name {
            // Check if function has access control
            let has_require_msg_sender =
                func_text.contains("require") && func_text.contains("msg.sender");
            let has_modifier = func_text.contains("onlyOwner") || func_text.contains("onlyAdmin");
            let is_internal = func_text.contains("internal") || func_text.contains("private");

            if !has_require_msg_sender && !has_modifier && !is_internal {
                let line = node.start_position().row + 1;
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::Medium, // Could be a false positive
                    line,
                    vulnerability_type: "Missing Access Control".to_string(),
                    message: "Sensitive function may lack access control".to_string(),
                    suggestion:
                        "Add require(msg.sender == owner) or use an access control modifier"
                            .to_string(),
                });
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_missing_access_control(&child, source_code, findings);
        }
    }
}

// Detector 5: Dangerous delegatecall
fn detect_dangerous_delegatecall(
    tree: &tree_sitter::Tree,
    source_code: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_dangerous_delegatecall(&root_node, source_code, findings);
}

fn find_dangerous_delegatecall(
    node: &tree_sitter::Node,
    source_code: &str,
    findings: &mut Vec<Finding>,
) {
    let text = &source_code[node.byte_range()];

    // Look for delegatecall usage
    if text.contains("delegatecall") {
        // Check if the target address is user-controlled (parameter or storage variable)
        let line = node.start_position().row + 1;

        // Look for patterns like: address.delegatecall or addr.delegatecall where addr might be controllable
        if node.kind() == "call_expression" || node.kind() == "expression_statement" {
            findings.push(Finding {
                severity: Severity::Critical,
                confidence: Confidence::Medium,  // Need to verify if user-controlled
                line,
                vulnerability_type: "Dangerous Delegatecall".to_string(),
                message: "delegatecall to potentially user-controlled address".to_string(),
                suggestion: "Ensure delegatecall target is hardcoded or strictly validated. Consider using library pattern.".to_string(),
            });
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_dangerous_delegatecall(&child, source_code, findings);
        }
    }
}

// Detector 6: Timestamp Dependence
fn detect_timestamp_dependence(
    tree: &tree_sitter::Tree,
    source_code: &str,
    findings: &mut Vec<Finding>,
) {
    let root_node = tree.root_node();
    find_timestamp_dependence(&root_node, source_code, findings);
}

fn find_timestamp_dependence(
    node: &tree_sitter::Node,
    source_code: &str,
    findings: &mut Vec<Finding>,
) {
    let text = &source_code[node.byte_range()];

    // Look for timestamp or block.timestamp in critical operations
    if (text.contains("block.timestamp") || text.contains("now"))
        && (node.kind() == "require_statement"
            || node.kind() == "if_statement"
            || node.kind() == "binary_expression")
    {
        let line = node.start_position().row + 1;
        findings.push(Finding {
            severity: Severity::Low,
            confidence: Confidence::Medium,
            line,
            vulnerability_type: "Timestamp Dependence".to_string(),
            message: "Using block.timestamp for critical logic can be manipulated by miners".to_string(),
            suggestion: "Avoid using block.timestamp for critical decisions. If needed, allow ~15 minute tolerance.".to_string(),
        });
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_timestamp_dependence(&child, source_code, findings);
        }
    }
}

// Detector 7: Unsafe Randomness
fn detect_unsafe_random(tree: &tree_sitter::Tree, source_code: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_unsafe_random(&root_node, source_code, findings);
}

fn find_unsafe_random(node: &tree_sitter::Node, source_code: &str, findings: &mut Vec<Finding>) {
    let text = &source_code[node.byte_range()];

    // Look for blockhash or block.number used in randomness
    let has_blockhash = text.contains("blockhash")
        || text.contains("block.number")
        || text.contains("block.difficulty");
    let has_modulo = text.contains("%");

    if has_blockhash && has_modulo {
        let line = node.start_position().row + 1;
        findings.push(Finding {
            severity: Severity::Medium,
            confidence: Confidence::High,
            line,
            vulnerability_type: "Unsafe Randomness".to_string(),
            message: "Using block properties for randomness is predictable".to_string(),
            suggestion: "Use Chainlink VRF or commit-reveal scheme for true randomness".to_string(),
        });
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_unsafe_random(&child, source_code, findings);
        }
    }
}

// Helper functions
fn find_child_by_kind<'a>(
    node: &'a tree_sitter::Node,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i)
            && child.kind() == kind
        {
            return Some(child);
        }
    }
    None
}

fn collect_statements<'a>(body: &'a tree_sitter::Node) -> Vec<tree_sitter::Node<'a>> {
    let mut statements = Vec::new();

    fn collect_recursive<'a>(
        node: tree_sitter::Node<'a>,
        statements: &mut Vec<tree_sitter::Node<'a>>,
    ) {
        let kind = node.kind();

        if kind == "expression_statement"
            || kind == "variable_declaration"
            || kind == "assignment_expression"
            || kind.ends_with("_statement")
        {
            statements.push(node);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_recursive(child, statements);
            }
        }
    }

    collect_recursive(*body, &mut statements);
    statements
}

fn is_external_call(node: &tree_sitter::Node, source_code: &str) -> bool {
    let text = &source_code[node.byte_range()];
    text.contains(".call{")
        || text.contains(".call(")
        || text.contains(".transfer(")
        || text.contains(".send(")
}

fn is_state_change(node: &tree_sitter::Node, source_code: &str) -> bool {
    let text = &source_code[node.byte_range()];

    if text.contains("balances[") || text.contains("balance[") {
        return text.contains("=") && !text.contains("==");
    }

    if node.kind() == "assignment_expression" {
        return true;
    }

    text.contains("-=") || text.contains("+=") || text.contains("=")
}

fn is_balance_mapping_change(node: &tree_sitter::Node, source_code: &str) -> bool {
    let text = &source_code[node.byte_range()];
    // Check specifically for balance mapping changes - classic reentrancy pattern
    (text.contains("balances[") || text.contains("balance["))
        && (text.contains("=") && !text.contains("=="))
}
