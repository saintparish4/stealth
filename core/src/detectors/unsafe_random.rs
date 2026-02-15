//! Detector: Unsafe on-chain randomness.
//!
//! Flags `keccak256(abi.encodePacked(block.timestamp, ...))` and `blockhash()`
//! patterns that miners or validators can predict or manipulate.

use crate::types::{Confidence, Finding, Severity};

pub fn detect_unsafe_random(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
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
