//! Detector: Storage collision in proxy / upgradeable contracts.
//!
//! Flags missing storage gaps, unprotected initializers, constructors in
//! upgradeable contracts, and non-EIP-1967 storage slot access.

use crate::types::{Confidence, Finding, Severity};

pub fn detect_storage_collision(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
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
