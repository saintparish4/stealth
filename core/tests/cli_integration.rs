//! CLI integration tests using assert_cmd.
//! These tests build and run the actual `stealth` binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn stealth() -> Command {
    Command::cargo_bin("stealth").expect("stealth binary")
}

#[test]
fn cli_version_flag() {
    stealth()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("stealth"));
}

#[test]
fn cli_help_flag() {
    stealth()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Smart contract security scanner"));
}

#[test]
fn cli_scan_json_produces_valid_json() {
    let assert = stealth()
        .args([
            "scan",
            "contracts/comprehensive-vulnerabilities.sol",
            "--format",
            "json",
        ])
        .assert();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(parsed.is_ok(), "JSON output should be valid: {}", stdout);

    let val = parsed.unwrap();
    assert!(val.get("findings").is_some(), "should have findings key");
    assert!(
        val.get("statistics").is_some(),
        "should have statistics key"
    );
}

#[test]
fn cli_scan_sarif_produces_valid_sarif() {
    let assert = stealth()
        .args([
            "scan",
            "contracts/comprehensive-vulnerabilities.sol",
            "--format",
            "sarif",
        ])
        .assert();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(parsed.is_ok(), "SARIF output should be valid JSON");

    let val = parsed.unwrap();
    assert!(val.get("$schema").is_some(), "SARIF should have $schema");
    assert_eq!(val.get("version").and_then(|v| v.as_str()), Some("2.1.0"));
}

#[test]
fn cli_exit_code_nonzero_for_vulnerable_contract() {
    stealth()
        .args([
            "scan",
            "contracts/comprehensive-vulnerabilities.sol",
            "--format",
            "json",
        ])
        .assert()
        .code(predicate::gt(0));
}

#[test]
fn cli_scan_nonexistent_file_still_runs() {
    let _ = stealth()
        .args([
            "scan",
            "contracts/this-does-not-exist.sol",
            "--format",
            "json",
        ])
        .assert();
}

#[test]
fn cli_scan_directory_recursive() {
    stealth()
        .args(["scan", "contracts", "--recursive", "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("findings"));
}
