//! Snapshot tests for JSON and SARIF output using insta.
//!
//! On first run: `cargo test` creates snapshot files in tests/snapshots/.
//! Review with: `cargo insta review`

use stealth_scanner::detectors::run_all_detectors;
use stealth_scanner::output::{format_json, format_sarif};
use stealth_scanner::scan::{calculate_statistics, new_solidity_parser, scan_file_with};

fn scan_test_contract() -> (Vec<stealth_scanner::Finding>, stealth_scanner::Statistics) {
    let path = if std::path::Path::new("contracts/comprehensive-vulnerabilities.sol").exists() {
        "contracts/comprehensive-vulnerabilities.sol"
    } else {
        "../contracts/comprehensive-vulnerabilities.sol"
    };

    let mut parser = new_solidity_parser().expect("parser");
    let outcome = scan_file_with(path, run_all_detectors, &mut parser);
    let stats = calculate_statistics(&outcome.findings);
    (outcome.findings, stats)
}

#[test]
fn snapshot_json_output_structure() {
    let (findings, stats) = scan_test_contract();
    let json = format_json(&findings, &stats);
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    // Snapshot the structure (keys and types) rather than exact values,
    // since line numbers may shift if test contracts change.
    let findings_count = value["findings"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(findings_count > 0, "should have findings");

    // Verify all findings have the new fields
    if let Some(arr) = value["findings"].as_array() {
        for f in arr {
            assert!(f.get("id").is_some(), "finding should have id");
            assert!(
                f.get("detector_id").is_some(),
                "finding should have detector_id"
            );
            assert!(f.get("severity").is_some());
            assert!(f.get("confidence").is_some());
            assert!(f.get("line").is_some());
            assert!(f.get("vulnerability_type").is_some());
        }
    }

    // Snapshot the statistics (stable across line changes)
    insta::assert_json_snapshot!("json_statistics", value["statistics"]);
}

#[test]
fn snapshot_sarif_output_structure() {
    let (findings, _stats) = scan_test_contract();
    let sarif = format_sarif(&findings);
    let value: serde_json::Value = serde_json::from_str(&sarif).expect("valid SARIF JSON");

    assert_eq!(value["version"].as_str(), Some("2.1.0"));
    assert!(value["runs"].as_array().is_some());

    let runs = value["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);

    let run = &runs[0];
    assert_eq!(run["tool"]["driver"]["name"].as_str(), Some("Stealth"));
    assert!(run["results"].as_array().is_some());
    assert!(run["tool"]["driver"]["rules"].as_array().is_some());

    let rules_count = run["tool"]["driver"]["rules"].as_array().unwrap().len();
    insta::assert_snapshot!("sarif_rules_count", rules_count.to_string());
}
