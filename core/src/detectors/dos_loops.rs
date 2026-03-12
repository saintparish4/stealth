//! Detector: Denial-of-service via unbounded loops.
//!
//! Flags unbounded iteration over dynamic arrays, external calls inside loops,
//! growing arrays without cleanup, and expensive delete operations in loops.
//! Uses AST function nodes for scoping and body analysis.

use crate::ast_utils::{func_body, function_name, function_visibility, node_text};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct DosLoopsDetector;

impl Detector for DosLoopsDetector {
    fn id(&self) -> &'static str {
        "dos-loops"
    }
    fn name(&self) -> &'static str {
        "Denial of Service via Loops"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC09:2025 - Denial of Service (DoS) Attacks")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            let visibility = function_visibility(func, ctx.source);
            if !visibility.is_externally_callable() {
                continue;
            }

            let name = function_name(func, ctx.source).unwrap_or("");
            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };
            let body_text = node_text(&body, ctx.source);
            let line = func.start_position().row + 1;

            let has_for_loop = body_text.contains("for (") || body_text.contains("for(");
            let has_while_loop = body_text.contains("while (") || body_text.contains("while(");

            if has_for_loop || has_while_loop {
                // Pattern 1: Loop over dynamic array
                let iterates_array = body_text.contains(".length")
                    || body_text.contains("< users")
                    || body_text.contains("< holders")
                    || body_text.contains("< recipients")
                    || body_text.contains("beneficiaries.length")
                    || body_text.contains("addresses.length")
                    || body_text.contains("whitelistedAddresses.length");

                let has_bound = body_text.contains("maxIterations")
                    || body_text.contains("batchSize")
                    || body_text.contains("limit")
                    || body_text.contains("MAX_");

                if iterates_array && !has_bound {
                    let has_external_call = body_text.contains(".call")
                        || body_text.contains(".transfer")
                        || body_text.contains(".send");
                    let has_storage_write =
                        body_text.contains(" = ") || body_text.contains("delete ");

                    let severity = if has_external_call {
                        Severity::High
                    } else if has_storage_write {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };

                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity,
                        confidence: Confidence::Medium,
                        line,
                        vulnerability_type: "Unbounded Loop".to_string(),
                        message: format!(
                            "Function '{}' has unbounded loop that may exceed gas limit",
                            name
                        ),
                        suggestion: "Add pagination or maximum iteration limit".to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }

                // Pattern 3: External call in loop
                if body_text.contains(".call")
                    || body_text.contains(".transfer")
                    || body_text.contains(".send")
                    || body_text.contains("safeTransfer")
                    || body_text.contains("_transfer(")
                {
                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        line,
                        vulnerability_type: "External Call in Loop".to_string(),
                        message:
                            "External calls in loop - single failure can revert entire transaction"
                                .to_string(),
                        suggestion:
                            "Use pull-over-push pattern: let users withdraw instead of pushing to them"
                                .to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }

                // Pattern 4: Delete from array in loop
                if body_text.contains("delete ") {
                    findings.push(Finding::from_detector(
                        self,
                        line,
                        Confidence::Medium,
                        "Expensive Loop Operation",
                        "Delete operations in loop are gas-expensive".to_string(),
                        "Consider swap-and-pop pattern or lazy deletion",
                    ));
                }
            }

            // Pattern 2: Push to array that's later iterated
            if body_text.contains(".push(") {
                let array_patterns = [
                    "users.push",
                    "holders.push",
                    "recipients.push",
                    "addresses.push",
                    "stakers.push",
                    "members.push",
                ];

                for pattern in array_patterns {
                    if body_text.contains(pattern) {
                        findings.push(Finding {
                            id: String::new(),
                            detector_id: self.id().to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Low,
                            line,
                            vulnerability_type: "Growing Array".to_string(),
                            message: "Array grows unbounded - iteration may exceed gas limit"
                                .to_string(),
                            suggestion:
                                "Use mapping instead of array, or implement cleanup mechanism"
                                    .to_string(),
                            remediation: None,
                            owasp_category: self.owasp_category().map(|s| s.to_string()),
                            file: None,
                        });
                        break;
                    }
                }
            }
        }
    }
}
