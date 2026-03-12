//! Detector: Reentrancy vulnerabilities.
//!
//! Flags external calls (`.call`, `.transfer`, `.send`) followed by state changes
//! without a reentrancy guard modifier. Uses AST traversal to identify call nodes
//! and assignment expressions, avoiding false positives from comments/strings.

use crate::ast_utils::{
    find_nodes_of_kind, func_body, function_visibility, has_reentrancy_guard, is_external_call,
    is_state_write,
};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::helpers::visibility_adjusted_confidence;
use crate::types::{Confidence, Finding, Severity};

pub struct ReentrancyDetector;

impl Detector for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "reentrancy"
    }
    fn name(&self) -> &'static str {
        "Reentrancy"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC02:2025 - Reentrancy Attacks")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            if has_reentrancy_guard(func, ctx.source) {
                continue;
            }

            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };

            let visibility = function_visibility(func, ctx.source);

            let calls = find_nodes_of_kind(&body, "call_expression");
            let mut earliest_external_call_line: Option<usize> = None;

            for call in &calls {
                if is_external_call(call, ctx.source) {
                    let line = call.start_position().row + 1;
                    if earliest_external_call_line.is_none_or(|prev| line < prev) {
                        earliest_external_call_line = Some(line);
                    }
                }
            }

            let call_line = match earliest_external_call_line {
                Some(l) => l,
                None => continue,
            };

            // Look for state writes AFTER the external call
            let assignments = find_nodes_of_kind(&body, "assignment_expression");
            let augmented = find_nodes_of_kind(&body, "augmented_assignment_expression");

            let state_change_line = assignments
                .iter()
                .chain(augmented.iter())
                .filter(|node| is_state_write(node))
                .map(|node| node.start_position().row + 1)
                .find(|&line| line > call_line);

            if let Some(change_line) = state_change_line {
                let base_confidence = Confidence::High;
                let adjusted = visibility_adjusted_confidence(base_confidence, visibility);

                let visibility_note = if !visibility.is_externally_callable() {
                    format!(" ({} function - lower risk)", visibility.as_str())
                } else {
                    String::new()
                };

                findings.push(Finding::from_detector(
                    self,
                    call_line,
                    adjusted,
                    "Reentrancy",
                    format!(
                        "External call at line {}, state change at line {}{}",
                        call_line, change_line, visibility_note
                    ),
                    "Move state changes before external call, or add nonReentrant modifier",
                ));
            }
        }
    }
}
