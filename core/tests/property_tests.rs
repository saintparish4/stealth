//! Property-based and structural correctness tests for the scanner engine.
//!
//! Properties covered:
//!   1. Panic safety     — scanner never panics on arbitrary input
//!   2. Suppression safety — parse_stealth_ignores never panics, line numbers valid
//!   3. Roundtrip        — findings serialize to JSON and back identically
//!   4. Idempotency      — scanning the same source twice yields identical findings
//!   5. Monotonicity     — adding a known-vulnerable pattern increases finding count

use proptest::prelude::*;
use std::fs;
use stealth_scanner::detectors::build_registry;
use stealth_scanner::scan::new_solidity_parser;
use stealth_scanner::suppression::{filter_findings_by_inline_ignores, parse_stealth_ignores};
use stealth_scanner::types::Finding;
use stealth_scanner::AnalysisContext;

// ---------------------------------------------------------------------------
// Shared helper: scan a Solidity source string, return findings.
//
// Mirrors scan_file_with but accepts an in-memory source so property tests
// don't need to touch the filesystem.
// ---------------------------------------------------------------------------

fn scan_source(source: &str) -> Vec<Finding> {
    let mut parser = new_solidity_parser().expect("parser init failed");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let ctx = AnalysisContext::new(&tree, source);
    let registry = build_registry();
    let mut findings = Vec::new();
    registry.run_all(&ctx, &mut findings);
    filter_findings_by_inline_ignores(findings, source)
}

// ---------------------------------------------------------------------------
// Property 1: Panic safety — scanner never panics on arbitrary input
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..Default::default() })]

    #[test]
    fn scanner_never_panics_on_random_input(input in "\\PC*") {
        // Any input is valid — the scanner must return findings or nothing,
        // never unwind. The `let _` prevents unused-result warnings.
        let _ = scan_source(&input);
    }
}

// ---------------------------------------------------------------------------
// Property 2: Suppression safety — parse_stealth_ignores never panics,
//             returned line numbers stay within the source line count
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..Default::default() })]

    #[test]
    fn suppression_parser_never_panics(
        prefix  in "[ \t]{0,4}",
        rule    in "[a-z_-]{0,30}",
        suffix  in "[^\n]{0,50}",
    ) {
        let source = format!(
            "pragma solidity ^0.8.0;\n{}// stealth-ignore: {}{}\ncontract T {{}}",
            prefix, rule, suffix
        );
        let total_lines = source.lines().count();
        let ignores = parse_stealth_ignores(&source);

        // parse_stealth_ignores returns (line_number, optional_type) tuples.
        // Each line number must be a positive value within the source + 1
        // (the +1 because an ignore on the last line covers the non-existent
        // next line, which is acceptable — the filter simply won't match).
        for (line_no, _) in &ignores {
            prop_assert!(
                *line_no >= 1 && *line_no <= total_lines + 1,
                "line_no {} out of range (source has {} lines)",
                line_no,
                total_lines
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 3: Roundtrip serialization — scan → JSON → deserialize → equal
// ---------------------------------------------------------------------------

#[test]
fn findings_roundtrip_serialization() {
    let dir = fs::read_dir("contracts").expect("contracts/ directory not found");
    for entry in dir.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "sol") {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {:?}: {}", path, e));

            let findings = scan_source(&source);
            let json = serde_json::to_string(&findings)
                .unwrap_or_else(|e| panic!("serialize failed for {:?}: {}", path, e));
            let deserialized: Vec<Finding> = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("deserialize failed for {:?}: {}", path, e));

            assert_eq!(findings, deserialized, "roundtrip mismatch for {:?}", path);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 4: Idempotency — scanning the same source twice produces
//             identical findings (same order, same content)
// ---------------------------------------------------------------------------

#[test]
fn scanning_is_idempotent() {
    let dir = fs::read_dir("contracts").expect("contracts/ directory not found");
    for entry in dir.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "sol") {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {:?}: {}", path, e));

            let run1 = scan_source(&source);
            let run2 = scan_source(&source);

            assert_eq!(run1, run2, "idempotency failed for {:?}", path);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 5: Monotonicity — adding a known-vulnerable pattern to a clean
//             contract increases the finding count by at least 1
// ---------------------------------------------------------------------------

#[test]
fn adding_vulnerability_increases_findings() {
    let clean = r#"
        pragma solidity ^0.8.0;
        contract Clean {
            uint256 public x;
            function safe() public {
                x = 1;
            }
        }
    "#;

    // Classic reentrancy: external call before state write, no guard.
    let vulnerable = r#"
        pragma solidity ^0.8.0;
        contract Vuln {
            mapping(address => uint256) public balances;
            function unsafe_withdraw() public {
                uint256 amount = balances[msg.sender];
                (bool ok,) = msg.sender.call{value: amount}("");
                require(ok);
                balances[msg.sender] = 0;
            }
        }
    "#;

    let clean_count = scan_source(clean).len();
    let vuln_count = scan_source(vulnerable).len();

    assert!(
        vuln_count > clean_count,
        "monotonicity failed: vulnerable contract ({} findings) should exceed \
         clean contract ({} findings)",
        vuln_count,
        clean_count
    );
}
