use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process;
use tree_sitter;
use walkdir::WalkDir;

mod heuristics;

#[derive(Parser)]
#[command(name = "stealth")]
#[command(version = "0.4.0")]
#[command(about = "Smart contract security scanner for Solidity - Enhanced with Self-Service & Visibility Heuristics", long_about = None)]
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

        /// Output format: terminal (default) or JSON
        #[arg(short, long, default_value = "terminal")]
        format: String,

        /// Recursively scan directories
        #[arg(short, long, default_value_t = false)]
        recursive: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Finding {
    severity: Severity,
    confidence: Confidence,
    line: usize,
    vulnerability_type: String,
    message: String,
    suggestion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    files_scanned: usize,
    vulnerabilities: usize,
    findings: Vec<Finding>,
    statistics: Statistics,
}

#[derive(Debug, Serialize, Deserialize)]
struct Statistics {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    confidence_high: usize,
    confidence_medium: usize,
    confidence_low: usize,
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
        Commands::Scan {
            file,
            format,
            recursive,
        } => {
            let output_format = match format.as_str() {
                "json" => OutputFormat::Json,
                "terminal" => OutputFormat::Terminal,
                _ => {
                    eprintln!(
                        "{} Invalid format '{}'. Use 'terminal' or 'json'",
                        "Error:".red().bold(),
                        format
                    );
                    process::exit(1);
                }
            };

            scan_path(&file, recursive, output_format);
        }
    }
}

#[derive(Debug, Clone)]
enum OutputFormat {
    Terminal,
    Json,
}

fn scan_path(path: &str, recursive: bool, format: OutputFormat) {
    let path_buf = PathBuf::from(path);

    if !path_buf.exists() {
        eprintln!("{} Path '{}' does not exist", "Error:".red().bold(), path);
        process::exit(1);
    }

    let mut all_findings = Vec::new();
    let mut files_scanned = 0;

    if path_buf.is_file() {
        // Single file scan
        if let Some(extension) = path_buf.extension() {
            if extension == "sol" {
                let findings = scan_file(path);
                files_scanned = 1;
                all_findings.extend(findings);
            } else {
                eprintln!("{} File must have .sol extension", "Error:".red().bold());
                process::exit(1);
            }
        }
    } else if path_buf.is_dir() {
        // Directory scan
        if recursive {
            for entry in WalkDir::new(&path_buf)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let file_path = entry.path();
                if file_path.is_file() {
                    if let Some(extension) = file_path.extension() {
                        if extension == "sol" {
                            let findings = scan_file(file_path.to_str().unwrap());
                            files_scanned += 1;

                            // Add file path to findings
                            let mut findings_with_path: Vec<Finding> = findings
                                .into_iter()
                                .map(|mut f| {
                                    f.file_path = Some(file_path.display().to_string());
                                    f
                                })
                                .collect();

                            all_findings.append(&mut findings_with_path);
                        }
                    }
                }
            }
        } else {
            eprintln!(
                "{} Path is a directory. Use --recursive to scan directories",
                "Error:".red().bold()
            );
            process::exit(1);
        }
    }

    // Calculate statistics
    let statistics = calculate_statistics(&all_findings);

    // Output results based on format
    match format {
        OutputFormat::Terminal => {
            print_terminal_output(path, files_scanned, &all_findings, &statistics);
        }
        OutputFormat::Json => {
            print_json_output(files_scanned, &all_findings, &statistics);
        }
    }

    // Exit with appropriate code for CI/CD
    if has_critical_findings(&all_findings) {
        process::exit(2); // Critical vulnerabilities found
    } else if !all_findings.is_empty() {
        process::exit(1); // Non-critical vulnerabilities found
    }
    // Exit 0 if no vulnerabilities found
    process::exit(0);
}

fn has_critical_findings(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical))
}

fn scan_file(file_path: &str) -> Vec<Finding> {
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
            return Vec::new();
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
        return Vec::new();
    }

    // Parse the source code
    let tree = match parser.parse(&source_code, None) {
        Some(tree) => tree,
        None => {
            eprintln!(
                "{} Failed to parse Solidity file. The syntax may be invalid.",
                file_path
            );
            return Vec::new();
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

    findings
}

fn calculate_statistics(findings: &[Finding]) -> Statistics {
    let mut stats = Statistics {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        confidence_high: 0,
        confidence_medium: 0,
        confidence_low: 0,
    };

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

fn print_terminal_output(
    path: &str,
    files_scanned: usize,
    findings: &[Finding],
    statistics: &Statistics,
) {
    println!("\n{}", "Vanguard Security Scan Results".bold().underline());
    println!("{} {}\n", "Scanning:".bold(), path);

    if findings.is_empty() {
        println!("{} No vulnerabilities detected.\n", "✓".green().bold());
    } else {
        let vuln_text = if findings.len() == 1 {
            "1 vulnerability".to_string()
        } else {
            format!("{} vulnerabilities", findings.len())
        };
        println!("{} {} found:\n", "⚠".yellow().bold(), vuln_text);

        for finding in findings {
            finding.print();
        }

        // Print statistics
        println!("\n{}", "Statistics Summary".bold().underline());
        println!("Files scanned: {}", files_scanned);
        println!("Total vulnerabilities: {}", findings.len());
        println!("\nBy Severity:");
        if statistics.critical > 0 {
            println!("  {}: {}", "Critical".red().bold(), statistics.critical);
        }
        if statistics.high > 0 {
            println!("  {}: {}", "High".red(), statistics.high);
        }
        if statistics.medium > 0 {
            println!("  {}: {}", "Medium".yellow(), statistics.medium);
        }
        if statistics.low > 0 {
            println!("  {}: {}", "Low".blue(), statistics.low);
        }

        println!("\nBy Confidence:");
        if statistics.confidence_high > 0 {
            println!("  High confidence: {}", statistics.confidence_high);
        }
        if statistics.confidence_medium > 0 {
            println!("  Medium confidence: {}", statistics.confidence_medium);
        }
        if statistics.confidence_low > 0 {
            println!("  Low confidence: {}", statistics.confidence_low);
        }
        println!();
    }
}

fn print_json_output(files_scanned: usize, findings: &[Finding], statistics: &Statistics) {
    let result = ScanResult {
        files_scanned,
        vulnerabilities: findings.len(),
        findings: findings.to_vec(),
        statistics: Statistics {
            critical: statistics.critical,
            high: statistics.high,
            medium: statistics.medium,
            low: statistics.low,
            confidence_high: statistics.confidence_high,
            confidence_medium: statistics.confidence_medium,
            confidence_low: statistics.confidence_low,
        },
    };

    match serde_json::to_string_pretty(&result) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!(
                "{} Failed to serialize results to JSON: {}",
                "Error:".red().bold(),
                e
            );
            process::exit(1);
        }
    }
}

// Detector 1: Reentrancy (with visibility-aware confidence adjustment)
fn detect_reentrancy(tree: &tree_sitter::Tree, source_code: &str, findings: &mut Vec<Finding>) {
    let root_node = tree.root_node();
    find_functions(&root_node, source_code, findings);
}

fn find_functions(node: &tree_sitter::Node, source_code: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "function_definition" {
        check_function_for_reentrancy(node, source_code, findings);
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            find_functions(&child, source_code, findings);
        }
    }
}

fn check_function_for_reentrancy(
    function_node: &tree_sitter::Node,
    source_code: &str,
    findings: &mut Vec<Finding>,
) {
    // Skip if function already has reentrancy guard
    if heuristics::has_reentrancy_guard(function_node, source_code) {
        return;
    }

    // Get function visibility for risk assessment
    let visibility = heuristics::get_function_visibility(function_node, source_code);
    
    // Skip private functions - they have no external reentrancy risk
    if visibility.risk_level() == 0 {
        return;
    }
    
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

                    // Determine base confidence from pattern clarity
                    let base_confidence = if is_balance_mapping_change(later_stmt, source_code) {
                        Confidence::High // Classic reentrancy pattern
                    } else {
                        Confidence::Medium // General state change after external call
                    };

                    // Adjust confidence based on function visibility
                    let (adjustment, visibility_note) = heuristics::visibility_confidence_adjustment(visibility);
                    let adjusted_confidence = adjust_confidence(base_confidence, adjustment);

                    // Determine severity based on risk level and pattern
                    let risk = visibility.risk_level();
                    let severity = if risk >= 3 && is_balance_mapping_change(later_stmt, source_code) {
                        Severity::Critical // High risk function + classic pattern
                    } else if risk >= 3 {
                        Severity::High // High risk function
                    } else {
                        Severity::Medium // Lower risk (internal functions)
                    };

                    let message = if !visibility.is_externally_callable() {
                        format!(
                            "External call at line {}, state change at line {} ({})",
                            line, state_line, visibility_note
                        )
                    } else {
                        format!(
                            "External call at line {}, state change at line {}",
                            line, state_line
                        )
                    };

                    findings.push(Finding {
                        severity,
                        confidence: adjusted_confidence,
                        line,
                        vulnerability_type: "Reentrancy".to_string(),
                        message,
                        suggestion:
                            "Move state changes before external call, or add nonReentrant modifier"
                                .to_string(),
                        file_path: None,
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
    // Look for .call() without return value checking
    if node.kind() == "expression_statement" {
        let text = &source_code[node.byte_range()];

        // Check if this is a .call() that doesn't capture the return value
        if text.contains(".call(") || text.contains(".call{") {
            // Verify it's not already checked with require/if or captured in a variable
            let trimmed = text.trim();
            if !trimmed.starts_with("(")
                && !trimmed.starts_with("require")
                && !trimmed.starts_with("if")
            {
                let line = node.start_position().row + 1;
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::High,  // Clear pattern
                    line,
                    vulnerability_type: "Unchecked Call".to_string(),
                    message: "External call return value is not checked".to_string(),
                    suggestion: "Check the return value: (bool success, ) = addr.call(...); require(success, \"Call failed\");".to_string(),
                    file_path: None,
                });
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
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

    // Look for tx.origin in require statements or conditionals (authentication pattern)
    if (node.kind() == "call_expression"
        || node.kind() == "require_statement"
        || node.kind() == "if_statement"
        || node.kind() == "binary_expression")
        && text.contains("tx.origin")
    {
        // Check if it's being used for comparison (authentication)
        if text.contains("==") || text.contains("!=") {
            let line = node.start_position().row + 1;
            findings.push(Finding {
                severity: Severity::High,
                confidence: Confidence::High, // Well-known anti-pattern
                line,
                vulnerability_type: "tx.origin Authentication".to_string(),
                message: "Using tx.origin for authorization is unsafe".to_string(),
                suggestion: "Use msg.sender instead of tx.origin for authentication checks"
                    .to_string(),
                file_path: None,
            });
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            find_tx_origin_usage(&child, source_code, findings);
        }
    }
}

// Detector 4: Missing Access Control (with self-service pattern detection)
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
        let visibility = heuristics::get_function_visibility(node, source_code);

        // Only check public/external functions
        if !visibility.is_externally_callable() {
            return;
        }

        // Skip view/pure functions - they don't need access control
        let is_view_or_pure = func_text.contains(" view ") 
            || func_text.contains(" pure ")
            || func_text.contains("\tview ")
            || func_text.contains("\tpure ");
        
        if is_view_or_pure {
            return;
        }

        // Sensitive operations that typically require access control
        let sensitive_keywords = [
            "selfdestruct", "suicide",        // Contract destruction
            "delegatecall",                   // Arbitrary code execution
            "setowner", "changeowner", "transferownership", // Ownership transfers
            "setadmin", "addadmin",           // Admin management
            "pause", "unpause",               // Circuit breakers
            "setfee", "setrate",              // Economic parameters
            "upgrade", "setimplementation",   // Upgrades
            "initialize", "init",             // Initializers
        ];
        
        let func_text_lower = func_text.to_lowercase();
        let is_sensitive = sensitive_keywords
            .iter()
            .any(|&kw| func_text_lower.contains(kw));

        if is_sensitive && !has_access_control(func_text) {
            // Skip self-service functions (users managing their own funds)
            if heuristics::should_skip_access_control_warning(node, source_code) {
                return;
            }

            let line = node.start_position().row + 1;
            let func_name = heuristics::get_function_name(node, source_code).unwrap_or("unknown");
            
            findings.push(Finding {
                severity: Severity::High,
                confidence: Confidence::High,
                line,
                vulnerability_type: "Missing Access Control".to_string(),
                message: format!(
                    "Function '{}' performs sensitive operations without access control",
                    func_name
                ),
                suggestion: "Add onlyOwner, onlyAdmin, or similar access control modifier".to_string(),
                file_path: None,
            });
        }

        // Check for withdraw functions without proper access control
        let withdraw_keywords = ["withdraw", "transfer", "send"];
        let has_withdraw_action = withdraw_keywords
            .iter()
            .any(|&kw| func_text_lower.contains(kw));

        if has_withdraw_action {
            // Skip self-service withdrawals (users withdrawing their own funds)
            if heuristics::should_skip_access_control_warning(node, source_code) {
                return;
            }

            // Check if function allows arbitrary recipient addresses
            let has_arbitrary_recipient = func_text.contains("address to")
                || func_text.contains("address _to")
                || func_text.contains("address recipient");

            if has_arbitrary_recipient && !has_access_control(func_text) {
                let line = node.start_position().row + 1;
                let func_name = heuristics::get_function_name(node, source_code).unwrap_or("unknown");
                
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::High,
                    line,
                    vulnerability_type: "Unrestricted Fund Transfer".to_string(),
                    message: format!(
                        "Function '{}' allows arbitrary fund transfers without access control",
                        func_name
                    ),
                    suggestion: "Add access control or restrict to msg.sender withdrawals only".to_string(),
                    file_path: None,
                });
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            find_missing_access_control(&child, source_code, findings);
        }
    }
}

fn has_access_control(func_text: &str) -> bool {
    // Check for access control modifiers
    let has_modifier = func_text.contains("onlyOwner")
        || func_text.contains("onlyAdmin")
        || func_text.contains("onlyRole")
        || func_text.contains("onlyAuthorized");

    // Check for require statements with msg.sender checks
    let has_require_sender = func_text.contains("require")
        && (func_text.contains("msg.sender == owner")
            || func_text.contains("msg.sender == admin")
            || func_text.contains("_owner"));

    has_modifier || has_require_sender
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
    if node.kind() == "function_definition" {
        let func_text = &source_code[node.byte_range()];

        if func_text.contains(".delegatecall(") {
            // Check if target address comes from function parameter (user-controlled)
            let has_address_param = func_text.contains("address ")
                && (func_text.contains("(address ") || func_text.contains(", address "));

            if has_address_param && !has_access_control(func_text) {
                let line = node.start_position().row + 1;
                findings.push(Finding {
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    line,
                    vulnerability_type: "Dangerous Delegatecall".to_string(),
                    message: "Delegatecall to user-supplied address without access control".to_string(),
                    suggestion: "Add strict access control or use a whitelist for delegatecall targets".to_string(),
                    file_path: None,
                });
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
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
    if node.kind() == "function_definition" {
        let func_text = &source_code[node.byte_range()];

        // Check for block.timestamp or now usage
        if func_text.contains("block.timestamp") || func_text.contains("now") {
            // Look for dangerous patterns
            let has_equality = func_text.contains("== block.timestamp")
                || func_text.contains("block.timestamp ==");
            let has_modulo = func_text.contains("% block.timestamp")
                || func_text.contains("block.timestamp %");

            // View/pure functions have lower severity
            let is_view = func_text.contains(" view ") || func_text.contains(" pure ");

            if has_equality || has_modulo {
                let severity = if has_modulo {
                    Severity::High
                } else {
                    Severity::Medium
                };
                
                let confidence = if is_view {
                    Confidence::Low
                } else {
                    Confidence::Medium
                };

                let message = if has_modulo {
                    "Using block.timestamp with modulo can be manipulated by miners".to_string()
                } else {
                    "Exact comparison with block.timestamp can be manipulated".to_string()
                };

                let line = node.start_position().row + 1;
                findings.push(Finding {
                    severity,
                    confidence,
                    line,
                    vulnerability_type: "Timestamp Dependence".to_string(),
                    message,
                    suggestion: "Use block.timestamp only for >15 minute precision; avoid equality checks".to_string(),
                    file_path: None,
                });
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
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
    // Only check at function level to avoid duplicates
    if node.kind() == "function_definition" {
        let func_text = &source_code[node.byte_range()];

        // Check for common insecure randomness patterns
        let bad_patterns = [
            "keccak256(abi.encodePacked(block.timestamp",
            "keccak256(abi.encodePacked(block.difficulty",
            "keccak256(abi.encodePacked(block.prevrandao",
            "keccak256(abi.encodePacked(block.number",
            "blockhash(",
        ];

        for pattern in &bad_patterns {
            if func_text.contains(pattern) {
                let line = node.start_position().row + 1;
                findings.push(Finding {
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    line,
                    vulnerability_type: "Unsafe Randomness".to_string(),
                    message: "Using block variables for randomness can be predicted/manipulated".to_string(),
                    suggestion: "Use Chainlink VRF or commit-reveal scheme for secure randomness".to_string(),
                    file_path: None,
                });
                break; // Only report once per function
            }
        }
    }

    // Recurse to find functions
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            find_unsafe_random(&child, source_code, findings);
        }
    }
}

// Helper functions
fn adjust_confidence(base: Confidence, adjustment: i8) -> Confidence {
    match (base, adjustment) {
        // Downgrade from High
        (Confidence::High, -2) => Confidence::Low,
        (Confidence::High, -1) => Confidence::Medium,
        // Downgrade from Medium
        (Confidence::Medium, -1 | -2) => Confidence::Low,
        // Keep base confidence otherwise
        _ => base,
    }
}

fn find_child_by_kind<'a>(
    node: &'a tree_sitter::Node,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            if child.kind() == kind {
                return Some(child);
            }
        }
    }
    None
}

fn collect_statements<'a>(body: &'a tree_sitter::Node) -> Vec<tree_sitter::Node<'a>> {
    let mut statements = Vec::new();
    collect_recursive(*body, &mut statements);
    statements
}

fn collect_recursive<'a>(node: tree_sitter::Node<'a>, statements: &mut Vec<tree_sitter::Node<'a>>) {
    let kind = node.kind();

    if kind == "expression_statement"
        || kind == "variable_declaration"
        || kind == "assignment_expression"
        || kind.ends_with("_statement")
    {
        statements.push(node);
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            collect_recursive(child, statements);
        }
    }
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
    // Check for balance mapping changes - classic reentrancy pattern indicator
    (text.contains("balances[") || text.contains("balance["))
        && (text.contains("=") && !text.contains("=="))
}
