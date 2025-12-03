use clap::{Parser};
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use tree_sitter;

#[derive(Parser)]
#[command(name = "stealth")]
#[command(version = "1.0.0")]
#[command(about = "Smart contract security scanner for Solidity contracts", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Scan a Solidity file or directory for vulnerabilities
    Scan {
        /// Path to the Solidity file or directory to scan
        file: String,
    },
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
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

#[derive(Debug)]
struct Finding {
    severity: Severity,
    line: usize,
    vulnerability_type: String,
    message: String,
    suggestion: String,
}

impl Finding {
    fn print(&self) {
        println!(
            "[{}] {} at line {}",
            self.severity.as_colored_str(),
            self.vulnerability_type.bold(),
            self.line
        );
        println!(" {} {}", "->".cyan(), self.message);
        println!(" {} {}", "Fix:".green().bold(), self.suggestion);
        println!();
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { file } => {
            let path = Path::new(&file);
            if path.is_dir() {
                scan_directory(path);
            } else if path.is_file() {
                scan_file(&file);
            } else {
                eprintln!(
                    "{} Path does not exist: '{}'",
                    "Error:".red().bold(),
                    file
                );
                process::exit(1);
            }
        }
    }
}

fn scan_directory(dir_path: &Path) {
    let mut sol_files = Vec::new();
    find_sol_files(dir_path, &mut sol_files);

    if sol_files.is_empty() {
        let dir_display = dir_path.display();
        eprintln!(
            "{} No Solidity files found in directory: '{}'",
            "Warning:".yellow().bold(),
            dir_display
        );
        return;
    }

    println!("\n{}", "Stealth Security Scan Results".bold().underline());
    let dir_display = dir_path.display();
    println!("{} {}\n", "Scanning directory:".bold(), dir_display);
    println!("Found {} file(s) to scan\n", sol_files.len());

    let mut total_findings = 0;
    for file_path in &sol_files {
        let findings = scan_file_internal(file_path);
        total_findings += findings.len();
    }

    println!("\n{}", "=".repeat(50).cyan());
    println!(
        "\n{} Scanned {} file(s), found {} total vulnerability/vulnerabilities",
        "Summary:".bold(),
        sol_files.len(),
        total_findings
    );
}

fn find_sol_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                find_sol_files(&path, files);
            } else if path.extension().and_then(|s| s.to_str()) == Some("sol") {
                files.push(path);
            }
        }
    }
}

fn scan_file(file_path: &str) {
    let path = Path::new(file_path);
    scan_file_internal(path);
}

fn scan_file_internal(file_path: &Path) -> Vec<Finding> {
    // Read the Solidity file
    let file_display = file_path.display();
    let source_code = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!(
                "{} Could not read file: '{}': {}",
                "Error:".red().bold(),
                file_display,
                e
            );
            return Vec::new();
        }
    };

    // Initialize parser with Solidity grammar
    let mut parser = tree_sitter::Parser::new();
    let language = unsafe { std::mem::transmute::<_, unsafe extern "C" fn() -> tree_sitter::Language>(tree_sitter_solidity::LANGUAGE)() };
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
            let file_display = file_path.display();
            eprintln!(
                "{} Failed to parse Solidity file: '{}'. The syntax may be invalid.",
                "Error:".red().bold(),
                file_display
            );
            return Vec::new();
        }
    };

    // Run all detectors
    let mut findings = Vec::new();

    detect_reentrancy(&tree, &source_code, &mut findings);
    detect_unchecked_calls(&tree, &source_code, &mut findings);
    detect_tx_origin(&tree, &source_code, &mut findings);

    // Display results
    println!("\n{}", "Stealth Security Scan Results".bold().underline());
    let file_display = file_path.display();
    println!("{} {}\n", "Scanning:".bold(), file_display);

    if findings.is_empty() {
        println!(
            "{} No vulnerabilities detected.\n",
            "Success:".green().bold()
        );
    } else {
        let count_msg = if findings.len() == 1 {
            "1 vulnerability".to_string()
        } else {
            format!("{} vulnerabilities", findings.len())
        };
        println!(
            "{} {} found:\n",
            "Warning:".yellow().bold(),
            count_msg
        );

        for finding in &findings {
            finding.print();
        }
    }

    findings
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

fn check_function_for_reentrancy(function_node: &tree_sitter::Node, source_code: &str, findings: &mut Vec<Finding>) {
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

                    findings.push(Finding {
                        severity: Severity::High,
                        line,
                        vulnerability_type: "Reentrancy".to_string(),
                        message: format!("External call at line {}, state change at line {}", line, state_line),
                        suggestion: "Move state changes before external call, or add nonReentrant modifier".to_string(),
                    });
                    return;
                }
            }
        }
    }
}

// Detector 2: Unchecked External Calls 
fn detect_unchecked_calls(tree: &tree_sitter::Tree, source_code: &str, findings: &mut Vec<Finding>) {
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
            if !trimmed.starts_with("(") && !trimmed.starts_with("require") && !trimmed.starts_with("if") {
                let line = node.start_position().row + 1;
                findings.push(Finding {
                    severity: Severity::Medium,
                    line,
                    vulnerability_type: "Unchecked Call".to_string(),
                    message: "External call return value is not checked".to_string(),
                    suggestion: "Check the return value: (bool success, ) = addr.call(...); require(sucess, \"Call failed\");".to_string(),
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
    if (node.kind() == "call_expression" || node.kind() == "require_statement" ||
    node.kind() == "if_statement" || node.kind() == "binary_expression") &&
    text.contains("tx.origin") {

        // Check if its being used for comparsion (authentication pattern)
        if text.contains("==") || text.contains("!=") {
            let line = node.start_position().row + 1;
            findings.push(Finding {
                severity: Severity::High,
                line,
                vulnerability_type: "tx.origin Authentication".to_string(),
                message: "Using tx.origin for authorization is unsafe".to_string(),
                suggestion: "Use msg.sender insteaf of tx.origin for authentication checks".to_string(),
            }); 
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_tx_origin_usage(&child, source_code, findings);
        }
    }
}

// Helper functions
fn find_child_by_kind<'a>(node: &'a tree_sitter::Node, kind: &str) -> Option<tree_sitter::Node<'a>> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == kind {
                return Some(child); 
            }
        }
    }
    None 
}

fn collect_statements<'a>(body: &'a tree_sitter::Node) -> Vec<tree_sitter::Node<'a>> {
    let mut statements = Vec::new();

    fn collect_recursive<'a>(node: tree_sitter::Node<'a>, statements: &mut Vec<tree_sitter::Node<'a>>) {
        let kind = node.kind();

        if kind == "expression_statement"
          || kind == "variable_declaration"
          || kind == "assignment_expression"
          || kind.ends_with("_statement") {
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

