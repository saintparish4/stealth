// Self-Service Pattern Detection
// Helps avoid false positives on functions like withdraw(), claim(), stake()
// where users are managing their own funds rather than arbitrary access
use tree_sitter::Node;

// Check if function name indicates a self-service pattern where users operate on their own funds
pub fn is_self_service_function_name(func_name: &str) -> bool {
    let lower_name = func_name.to_lowercase();

    // Common self-service patterns in DeFi contracts
    let self_service_names = [
        // Deposit/withdrawal operations
        "deposit",
        "withdraw",
        "withdrawall",
        "withdrawto",
        // Claiming rewards
        "claim",
        "claimrewards",
        "claimall",
        // Staking operations
        "stake",
        "unstake",
        "restake",
        // Token operations (user's own tokens)
        "transfer",
        "approve",
        "transferfrom",
        // Vault/pool operations
        "mint",
        "burn",
        "redeem",
        "redeemall",
        // Vesting operations
        "release",
        "releaseall",
        "vest",
        // Exit patterns
        "exit",
        "leave",
        "emergencywithdraw",
        // Compound/harvest operations
        "harvest",
        "compound",
        "reinvest",
    ];

    self_service_names
        .iter()
        .any(|&name| lower_name.contains(name))
}

// Analyze function body to determine if it only operates on msg.sender's data
pub fn is_self_service_pattern(node: &Node, source: &str) -> bool {
    let func_text = &source[node.start_byte()..node.end_byte()];

    // Check for msg.sender-scoped mapping access patterns
    let has_sender_mapping = func_text.contains("balances[msg.sender]")
        || func_text.contains("_balances[msg.sender]")
        || func_text.contains("deposits[msg.sender]")
        || func_text.contains("stakes[msg.sender]")
        || func_text.contains("rewards[msg.sender]")
        || func_text.contains("userInfo[msg.sender]");

    // Check for transfers to msg.sender
    let transfer_to_sender = func_text.contains("payable(msg.sender)")
        || func_text.contains("msg.sender.call{value")
        || func_text.contains(".transfer(msg.sender")
        || func_text.contains("safeTransfer(msg.sender");

    // Check for token transfers to msg.sender
    let token_to_sender = func_text.contains("transfer(msg.sender,")
        || func_text.contains("_transfer(address(this), msg.sender");

    // Check for require statements that validate msg.sender ownership
    // Common patterns: require(schedule.beneficiary == msg.sender)
    let has_sender_check = (func_text.contains("require") || func_text.contains("if"))
        && (func_text.contains("== msg.sender") || func_text.contains("msg.sender =="))
        && (func_text.contains(".beneficiary") 
            || func_text.contains(".owner") 
            || func_text.contains("[msg.sender]"));

    // Check if function accepts arbitrary address parameters
    // If it does, it's not purely self-service
    let has_address_param = func_text.contains("address to")
        || func_text.contains("address _to")
        || func_text.contains("address recipient")
        || func_text.contains("address payable to");

    // Self-service pattern: operates on msg.sender's data OR transfers to msg.sender,
    // OR checks that caller owns the resource, without accepting arbitrary destination addresses
    (has_sender_mapping || transfer_to_sender || token_to_sender || has_sender_check) 
        && !has_address_param
}

// Determine if access control warning should be skipped for a self-service function
pub fn should_skip_access_control_warning(node: &Node, source: &str) -> bool {
    let func_name = get_function_name(node, source).unwrap_or_default();

    // Check both name-based and behavior-based detection
    let is_self_service_name = is_self_service_function_name(&func_name);
    let is_self_service_body = is_self_service_pattern(node, source);

    // Skip warning only if both checks indicate self-service
    is_self_service_name && is_self_service_body
}

// Function Visibility Awareness
// Adjusts confidence levels for reentrancy detection based on function visibility
// Private/internal functions have significantly lower reentrancy risk than public/external

// Solidity visibility levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Visibility {
    Public,   // Callable by anyone
    External, // Callable externally
    Internal, // Callable internally or by derived contracts
    Private,  // Callable within the contract
}

impl Visibility {
    // Returns reentrancy risk level (higher = more risky)
    pub fn risk_level(&self) -> u8 {
        match self {
            Visibility::External => 3, // Highest risk - external entry point
            Visibility::Public => 3,   // High risk - callable by anyone
            Visibility::Internal => 1, // Lower risk - limited to contract hierarchy
            Visibility::Private => 0,  // Minimal risk - only this contract
        }
    }

    // Check if function can be called externally
    pub fn is_externally_callable(&self) -> bool {
        matches!(self, Visibility::Public | Visibility::External)
    }
}

// Extract visibility modifier from function definition node
pub fn get_function_visibility(node: &Node, source: &str) -> Visibility {
    if node.kind() != "function_definition" {
        return Visibility::Public; // Default assumption for safety
    }

    let func_text = &source[node.start_byte()..node.end_byte()];

    // Parse function signature (before opening brace) for visibility keywords
    let signature_end = func_text.find('{').unwrap_or(func_text.len());
    let signature = &func_text[..signature_end];

    if signature.contains(" private") || signature.contains("\tprivate") {
        Visibility::Private
    } else if signature.contains(" internal") || signature.contains("\tinternal") {
        Visibility::Internal
    } else if signature.contains(" external") || signature.contains("\texternal") {
        Visibility::External
    } else {
        // Default to public if not specified (Solidity default)
        Visibility::Public
    }
}

// Adjust reentrancy confidence based on function visibility
// Returns (confidence_modifier, explanation_note)
pub fn visibility_confidence_adjustment(visibility: Visibility) -> (i8, &'static str) {
    match visibility {
        Visibility::External => (0, "external function"),
        Visibility::Public => (0, "public function"),
        Visibility::Internal => (-1, "internal function - lower risk"),
        Visibility::Private => (-2, "private function - minimal risk"),
    }
}

// Helper Functions

// Extract function name from function_definition node
pub fn get_function_name<'a>(node: &Node, source: &'a str) -> Option<&'a str> {
    if node.kind() != "function_definition" {
        return None;
    }

    // Walk child nodes to find the identifier
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "function_name" {
            return Some(&source[child.start_byte()..child.end_byte()]);
        }
    }

    None
}

// Check if function has any of the specified modifiers
pub fn has_modifier(node: &Node, source: &str, modifiers: &[&str]) -> bool {
    let func_text = &source[node.start_byte()..node.end_byte()];
    modifiers.iter().any(|m| func_text.contains(m))
}

// Check if function has reentrancy guard modifiers
pub fn has_reentrancy_guard(node: &Node, source: &str) -> bool {
    has_modifier(
        node,
        source,
        &[
            "nonReentrant",
            "noReentrant",
            "reentrancyGuard",
            "lock",
            "mutex",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_service_function_names() {
        assert!(is_self_service_function_name("withdraw"));
        assert!(is_self_service_function_name("withdrawAll"));
        assert!(is_self_service_function_name("claim"));
        assert!(is_self_service_function_name("claimRewards"));
        assert!(is_self_service_function_name("stake"));
        assert!(is_self_service_function_name("unstake"));
        assert!(is_self_service_function_name("deposit"));

        // Non-self-service names
        assert!(!is_self_service_function_name("transferOwnership"));
        assert!(!is_self_service_function_name("setFee"));
        assert!(!is_self_service_function_name("pause"));
        assert!(!is_self_service_function_name("initialize"));
    }

    #[test]
    fn test_visibility_risk_levels() {
        assert_eq!(Visibility::External.risk_level(), 3);
        assert_eq!(Visibility::Public.risk_level(), 3);
        assert_eq!(Visibility::Internal.risk_level(), 1);
        assert_eq!(Visibility::Private.risk_level(), 0);
    }

    #[test]
    fn test_externally_callable() {
        assert!(Visibility::Public.is_externally_callable());
        assert!(Visibility::External.is_externally_callable());
        assert!(!Visibility::Internal.is_externally_callable());
        assert!(!Visibility::Private.is_externally_callable());
    }
}
