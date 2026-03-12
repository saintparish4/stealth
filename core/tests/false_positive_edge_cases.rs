//! S1.5c → S2: False-positive edge case tests.
//!
//! These tests verify that AST-based detectors do NOT fire on safe code where
//! the old string-matching detectors would have produced false positives.
//! After the S2 AST rewrite, all assertions confirm zero false positives.

use stealth_scanner::detector_trait::{AnalysisContext, Detector};
use stealth_scanner::detectors::{
    DangerousDelegatecallDetector, ReentrancyDetector, TimestampDetector, TxOriginDetector,
};
use stealth_scanner::scan::new_solidity_parser;
use stealth_scanner::types::Finding;

static FP_CONTRACT: &str = include_str!("../contracts/false-positive-edge-cases.sol");

fn run_detector(detector: &dyn Detector, source: &str) -> Vec<Finding> {
    let mut parser = new_solidity_parser().expect("parser");
    let tree = parser.parse(source, None).expect("parse");
    let ctx = AnalysisContext::new(&tree, source);
    let mut findings = Vec::new();
    detector.run(&ctx, &mut findings);
    findings
}

// -------------------------------------------------------------------
// FP 1: `.call` in a comment must NOT trigger reentrancy detector
// -------------------------------------------------------------------

#[test]
fn fp_call_in_comment_does_not_trigger_reentrancy() {
    let findings = run_detector(&ReentrancyDetector, FP_CONTRACT);
    let has_fp = findings
        .iter()
        .any(|f| f.detector_id == "reentrancy" && f.vulnerability_type == "Reentrancy");
    assert!(
        !has_fp,
        "AST-based reentrancy detector must not trigger on .call in a comment"
    );
}

// -------------------------------------------------------------------
// FP 2: `.call` in a string literal must NOT trigger reentrancy
// -------------------------------------------------------------------

#[test]
fn fp_call_in_string_literal_does_not_trigger_reentrancy() {
    let source = r#"
pragma solidity ^0.8.0;
contract StringCallFP {
    function f() external {
        string memory s = "addr.call{value: x}()";
        balances[msg.sender] = 0;
    }
}
"#;
    let findings = run_detector(&ReentrancyDetector, source);
    let has_fp = findings.iter().any(|f| f.detector_id == "reentrancy");
    assert!(
        !has_fp,
        "AST-based reentrancy detector must not trigger on .call in string literal"
    );
}

// -------------------------------------------------------------------
// FP 3: `tx.origin` in a comment must NOT trigger tx-origin detector
// -------------------------------------------------------------------

#[test]
fn fp_tx_origin_in_comment_does_not_trigger() {
    let source = r#"
pragma solidity ^0.8.0;
contract CommentTxOriginFP {
    function f() public view returns (bool) {
        // Guard: tx.origin == msg.sender is an anti-pattern
        return true;
    }
}
"#;
    let findings = run_detector(&TxOriginDetector, source);
    let has_fp = findings.iter().any(|f| f.detector_id == "tx-origin");
    assert!(
        !has_fp,
        "AST-based tx-origin detector must not trigger on tx.origin in comment"
    );
}

// -------------------------------------------------------------------
// FP 4: `delegatecall` in an event name must NOT trigger delegatecall
// -------------------------------------------------------------------

#[test]
fn fp_delegatecall_in_event_name_does_not_trigger() {
    let source = r#"
pragma solidity ^0.8.0;
contract EventDelegatecallFP {
    event DelegatecallExecuted(address indexed target, bool success);

    function f(address target) external {
        emit DelegatecallExecuted(target, true);
    }
}
"#;
    let findings = run_detector(&DangerousDelegatecallDetector, source);
    let has_fp = findings
        .iter()
        .any(|f| f.detector_id == "dangerous-delegatecall");
    assert!(
        !has_fp,
        "AST-based delegatecall detector must not trigger on event name"
    );
}

// -------------------------------------------------------------------
// FP 5: `block.timestamp` in a string literal must NOT trigger
// -------------------------------------------------------------------

#[test]
fn fp_block_timestamp_in_string_literal_does_not_trigger() {
    let source = r#"
pragma solidity ^0.8.0;
contract StringTimestampFP {
    function f() external pure returns (string memory) {
        return "block.timestamp == deadline is dangerous";
    }
}
"#;
    let findings = run_detector(&TimestampDetector, source);
    let has_fp = findings
        .iter()
        .any(|f| f.detector_id == "timestamp-dependence");
    assert!(
        !has_fp,
        "AST-based timestamp detector must not trigger on block.timestamp in string literal"
    );
}

// -------------------------------------------------------------------
// FP 6: `delegatecall` in a comment must NOT trigger delegatecall
// -------------------------------------------------------------------

#[test]
fn fp_delegatecall_in_comment_does_not_trigger() {
    let source = r#"
pragma solidity ^0.8.0;
contract CommentDelegatecallFP {
    function upgrade(address newImpl) external {
        // Previously used: newImpl.delegatecall("") but removed for safety
        // Now using a safe upgrade pattern
        implementation = newImpl;
    }
}
"#;
    let findings = run_detector(&DangerousDelegatecallDetector, source);
    let has_fp = findings
        .iter()
        .any(|f| f.detector_id == "dangerous-delegatecall");
    assert!(
        !has_fp,
        "AST-based delegatecall detector must not trigger on .delegatecall in comment"
    );
}
