//! Shared helpers for detectors: self-service patterns, visibility, modifiers.

use crate::types::{Confidence, Visibility};

/// Check if a function name indicates a self-service pattern
pub fn is_self_service_function_name(func_name: &str) -> bool {
    let lower_name = func_name.to_lowercase();
    let self_service_names = [
        "deposit", "withdraw", "withdrawall", "withdrawto", "claim", "claimreward",
        "claimrewards", "claimall", "stake", "unstake", "restake", "transfer",
        "approve", "transferfrom", "mint", "burn", "redeem", "redeemall", "exit",
        "leave", "emergencywithdraw", "harvest", "compound", "reinvest",
    ];
    self_service_names.iter().any(|&name| lower_name.contains(name))
}

/// Check if a function operates only on msg.sender's data
pub fn is_self_service_pattern(func_text: &str) -> bool {
    let has_sender_mapping = func_text.contains("balances[msg.sender]")
        || func_text.contains("_balances[msg.sender]")
        || func_text.contains("deposits[msg.sender]")
        || func_text.contains("stakes[msg.sender]")
        || func_text.contains("rewards[msg.sender]")
        || func_text.contains("userInfo[msg.sender]");
    let transfer_to_sender = func_text.contains("payable(msg.sender)")
        || func_text.contains("msg.sender.call{value")
        || func_text.contains("(msg.sender).transfer(")
        || func_text.contains("safeTransfer(msg.sender");
    let token_to_sender = func_text.contains("transfer(msg.sender,")
        || func_text.contains("_transfer(address(this), msg.sender");
    let has_arbitrary_recipient = func_text.contains("address to,")
        || func_text.contains("address _to,")
        || func_text.contains("address recipient,")
        || func_text.contains("address _recipient,");
    (has_sender_mapping || transfer_to_sender || token_to_sender) && !has_arbitrary_recipient
}

/// Combined check for self-service pattern (name + body analysis)
pub fn should_skip_access_control_warning(func_name: &str, func_text: &str) -> bool {
    is_self_service_function_name(func_name) && is_self_service_pattern(func_text)
}

/// Extract function visibility from function text
pub fn get_function_visibility(func_text: &str) -> Visibility {
    let signature_end = func_text.find('{').unwrap_or(func_text.len());
    let signature = &func_text[..signature_end];
    if signature.contains(" private") || signature.contains("\tprivate") || signature.contains("(private") {
        Visibility::Private
    } else if signature.contains(" internal") || signature.contains("\tinternal") || signature.contains("(internal") {
        Visibility::Internal
    } else if signature.contains(" external") || signature.contains("\texternal") || signature.contains("(external") {
        Visibility::External
    } else {
        Visibility::Public
    }
}

/// Get confidence level based on visibility (reentrancy)
pub fn visibility_adjusted_confidence(base: Confidence, visibility: Visibility) -> Confidence {
    match (base, visibility) {
        (Confidence::High, Visibility::Private) => Confidence::Low,
        (Confidence::High, Visibility::Internal) => Confidence::Medium,
        (Confidence::Medium, Visibility::Private) => Confidence::Low,
        _ => base,
    }
}

/// Extract function name from function text
pub fn extract_function_name(func_text: &str) -> String {
    if let Some(start) = func_text.find("function ") {
        let after_function = &func_text[start + 9..];
        if let Some(end) = after_function.find('(') {
            return after_function[..end].trim().to_string();
        }
    }
    String::new()
}

/// Check if function has a modifier
pub fn has_modifier(func_text: &str, modifiers: &[&str]) -> bool {
    modifiers.iter().any(|m| func_text.contains(m))
}

/// Check for reentrancy guard modifiers
pub fn has_reentrancy_guard(func_text: &str) -> bool {
    has_modifier(func_text, &["nonReentrant", "noReentrant", "reentrancyGuard", "lock"])
}

/// Check if function has access control
pub fn has_access_control(func_text: &str) -> bool {
    let has_mod = func_text.contains("onlyOwner")
        || func_text.contains("onlyAdmin")
        || func_text.contains("onlyRole")
        || func_text.contains("onlyAuthorized");
    let has_require_sender = func_text.contains("require")
        && (func_text.contains("msg.sender == owner")
            || func_text.contains("msg.sender == admin")
            || func_text.contains("_owner"));
    has_mod || has_require_sender
}

/// Normalize vulnerability type for matching (suppression, baseline)
pub fn normalize_vuln_type(s: &str) -> String {
    s.to_lowercase().replace('-', " ").replace('_', " ")
}
