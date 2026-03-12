//! Detector: Unchecked external call return values.
//!
//! Flags `.call{...}(...)` statements where the return value is not captured
//! or checked with `require`. Uses AST to inspect expression_statement nodes
//! containing external calls that aren't wrapped in an assignment.

use crate::ast_utils::{find_nodes_of_kind, is_external_call, is_inside_node_of_kind, node_text};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct UncheckedCallsDetector;

impl Detector for UncheckedCallsDetector {
    fn id(&self) -> &'static str {
        "unchecked-calls"
    }
    fn name(&self) -> &'static str {
        "Unchecked External Call Return Values"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC04:2025 - Lack of Input Validation")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        let expr_stmts = find_nodes_of_kind(&ctx.tree.root_node(), "expression_statement");
        for stmt in &expr_stmts {
            let calls = find_nodes_of_kind(stmt, "call_expression");
            for call in &calls {
                if !is_external_call(call, ctx.source) {
                    continue;
                }
                // If the call is inside an assignment or variable declaration, return is captured
                if is_inside_node_of_kind(call, "assignment_expression")
                    || is_inside_node_of_kind(call, "variable_declaration_statement")
                    || is_inside_node_of_kind(call, "variable_declaration")
                {
                    continue;
                }
                let text = node_text(stmt, ctx.source).trim().to_string();
                if text.starts_with("(bool") || text.starts_with("bool") || text.contains("= ") {
                    continue;
                }
                findings.push(Finding::from_detector(
                    self,
                    stmt.start_position().row + 1,
                    Confidence::High,
                    "Unchecked Call",
                    "External call return value is not checked".to_string(),
                    "Check the return value: (bool success, ) = addr.call(...); require(success);",
                ));
                break;
            }
        }
    }
}
