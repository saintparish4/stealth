//! Detector: Missing access control on sensitive functions.
//!
//! Flags public/external functions that perform sensitive operations (selfdestruct,
//! delegatecall, ownership changes, etc.) or allow arbitrary fund transfers without
//! access-control modifiers or `require(msg.sender == ...)` checks.
//! Uses AST for function analysis and expanded modifier matching.

use crate::ast_utils::{
    func_body, function_name, function_visibility, has_access_control, node_text,
};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::helpers::should_skip_access_control_warning;
use crate::types::{Confidence, Finding, Severity};

pub struct AccessControlDetector;

impl Detector for AccessControlDetector {
    fn id(&self) -> &'static str {
        "access-control"
    }
    fn name(&self) -> &'static str {
        "Missing Access Control"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC01:2025 - Access Control Vulnerabilities")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            let visibility = function_visibility(func, ctx.source);

            if !visibility.is_externally_callable() {
                continue;
            }

            let name = match function_name(func, ctx.source) {
                Some(n) => n,
                None => continue,
            };

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

            let name_lower = name.to_lowercase();
            if pure_user_functions
                .iter()
                .any(|&puf| name_lower == puf.to_lowercase())
            {
                continue;
            }

            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };
            let body_text = node_text(&body, ctx.source);
            let func_text = node_text(func, ctx.source);

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
                .any(|&kw| body_text.to_lowercase().contains(&kw.to_lowercase()));

            if is_sensitive && !has_access_control(func, ctx.source) {
                if should_skip_access_control_warning(name, func_text) {
                    continue;
                }

                findings.push(Finding::from_detector(
                    self,
                    func.start_position().row + 1,
                    Confidence::High,
                    "Missing Access Control",
                    format!(
                        "Function '{}' performs sensitive operations without access control",
                        name
                    ),
                    "Add onlyOwner, onlyAdmin, or similar access control modifier",
                ));
            }

            // Check for withdraw functions without access control
            let withdraw_keywords = ["withdraw", "transfer", "send"];
            let has_withdraw_action = withdraw_keywords.iter().any(|&kw| name_lower.contains(kw));

            if has_withdraw_action {
                if should_skip_access_control_warning(name, func_text) {
                    continue;
                }

                let has_arbitrary_recipient = func_text.contains("address to")
                    || func_text.contains("address _to")
                    || func_text.contains("address recipient");

                if has_arbitrary_recipient && !has_access_control(func, ctx.source) {
                    findings.push(Finding::from_detector(
                        self,
                        func.start_position().row + 1,
                        Confidence::High,
                        "Unrestricted Fund Transfer",
                        format!(
                            "Function '{}' allows arbitrary fund transfers without access control",
                            name
                        ),
                        "Add access control or restrict to msg.sender withdrawals only",
                    ));
                }
            }
        }
    }
}
