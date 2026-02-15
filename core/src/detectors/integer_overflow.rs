//! Detector: Integer overflow / underflow.
//!
//! For Solidity >=0.8: flags arithmetic inside `unchecked { }` blocks.
//! For Solidity <0.8: flags raw arithmetic on uint types without SafeMath.

use crate::types::{Confidence, Finding, Severity};

pub fn detect_integer_overflow(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
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
