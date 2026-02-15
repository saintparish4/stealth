// ============================================================================
// Stealth - Smart Contract Security Scanner (binary)
// Version 0.4.0 - Thin CLI; detectors live in stealth_scanner::detectors.
// ============================================================================

use clap::{Parser, Subcommand};
use std::path::Path;
use stealth_scanner::*;
use stealth_scanner::detectors::run_all_detectors;

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "stealth")]
#[command(about = "Smart contract security scanner for Solidity", long_about = None)]
#[command(version = "0.4.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        path: String,
        #[arg(short, long, default_value = "terminal")]
        format: String,
        #[arg(short, long)]
        recursive: bool,
        #[arg(long)]
        baseline: Option<String>,
    },
}

// ============================================================================
// MAIN
// ============================================================================

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            recursive,
            baseline,
        } => {
            let mut findings = if Path::new(&path).is_dir() {
                scan_directory_with(&path, recursive, run_all_detectors)
            } else {
                scan_file_with(&path, run_all_detectors)
            };

            if let Some(ref baseline_path) = baseline {
                let baseline_set = load_baseline(baseline_path);
                findings = filter_findings_by_baseline(findings, &baseline_set);
            }

            let stats = calculate_statistics(&findings);

            match format.as_str() {
                "json" => print_json(&findings, &stats),
                "sarif" => stealth_scanner::output::print_sarif(&findings),
                _ => print_results(&path, &findings, &stats),
            }

            let exit_code = if stats.critical > 0 || stats.high > 0 {
                2
            } else if stats.medium > 0 {
                1
            } else {
                0
            };

            std::process::exit(exit_code);
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use stealth_scanner::detectors::*;
    use stealth_scanner::*;
    use std::collections::HashSet;

    /// Parse a Solidity source string into a tree for detector tests.
    fn parse_solidity(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_solidity::LANGUAGE.into())
            .expect("Solidity language");
        parser.parse(source, None).expect("parse")
    }

    #[test]
    fn test_self_service_function_names() {
        assert!(is_self_service_function_name("withdraw"));
        assert!(is_self_service_function_name("withdrawAll"));
        assert!(is_self_service_function_name("claim"));
        assert!(is_self_service_function_name("claimRewards"));
        assert!(is_self_service_function_name("stake"));
        assert!(is_self_service_function_name("deposit"));

        assert!(!is_self_service_function_name("setOwner"));
        assert!(!is_self_service_function_name("pause"));
        assert!(!is_self_service_function_name("initialize"));
    }

    #[test]
    fn test_self_service_pattern() {
        let safe_withdraw = r#"
            function withdraw() public {
                uint256 amt = balances[msg.sender];
                balances[msg.sender] = 0;
                payable(msg.sender).transfer(amt);
            }
        "#;
        assert!(is_self_service_pattern(safe_withdraw));

        let unsafe_withdraw = r#"
            function withdraw(address to, uint256 amount) public {
                balances[to] -= amount;
                payable(to).transfer(amount);
            }
        "#;
        assert!(!is_self_service_pattern(unsafe_withdraw));
    }

    #[test]
    fn test_visibility_detection() {
        assert_eq!(
            get_function_visibility("function foo() public { }"),
            Visibility::Public
        );
        assert_eq!(
            get_function_visibility("function foo() external { }"),
            Visibility::External
        );
        assert_eq!(
            get_function_visibility("function foo() internal { }"),
            Visibility::Internal
        );
        assert_eq!(
            get_function_visibility("function foo() private { }"),
            Visibility::Private
        );
    }

    #[test]
    fn test_visibility_confidence_adjustment() {
        assert_eq!(
            visibility_adjusted_confidence(Confidence::High, Visibility::Public),
            Confidence::High
        );
        assert_eq!(
            visibility_adjusted_confidence(Confidence::High, Visibility::Private),
            Confidence::Low
        );
        assert_eq!(
            visibility_adjusted_confidence(Confidence::High, Visibility::Internal),
            Confidence::Medium
        );
    }

    // ========== Detector tests: minimal Solidity snippets, assert on findings ==========

    #[test]
    fn detector_reentrancy_finds_state_change_after_call() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_reentrancy(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "reentrancy detector should find state change after call"
        );
        let f = &findings[0];
        assert_eq!(f.vulnerability_type, "Reentrancy");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn detector_tx_origin_finds_auth_use() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    address owner;
    function withdraw() public {
        require(tx.origin == owner);
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_tx_origin(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "tx.origin detector should find auth use"
        );
        assert_eq!(findings[0].vulnerability_type, "tx.origin Authentication");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detector_timestamp_dependence_finds_modulo() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function claim() public {
        require(block.timestamp % 15 == 0);
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_timestamp_dependence(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "timestamp detector should find modulo use"
        );
        assert_eq!(findings[0].vulnerability_type, "Timestamp Dependence");
    }

    #[test]
    fn detector_unsafe_random_finds_block_properties() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function lottery() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % 100;
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_unsafe_random(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "unsafe random detector should find block-based randomness"
        );
        assert_eq!(findings[0].vulnerability_type, "Unsafe Randomness");
    }

    #[test]
    fn detector_access_control_finds_sensitive_without_auth() {
        // Withdraw with arbitrary recipient (no self-service): triggers "Unrestricted Fund Transfer"
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function withdrawAll(address to) public {
        (bool ok,) = payable(to).call{value: address(this).balance}("");
        require(ok);
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_access_control(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "access control detector should find withdraw with arbitrary recipient"
        );
        assert_eq!(
            findings[0].vulnerability_type, "Unrestricted Fund Transfer",
            "expected Unrestricted Fund Transfer when withdraw allows arbitrary address"
        );
    }

    #[test]
    fn detector_unchecked_erc20_flags_transfer_without_check() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function pay(address token, address to, uint256 amt) public {
        IERC20(token).transfer(to, amt);
    }
}
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_unchecked_erc20(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "unchecked ERC20 detector should find transfer without check"
        );
        let vuln_type = &findings[0].vulnerability_type;
        assert!(
            vuln_type.contains("ERC20") || vuln_type.contains("SafeERC20"),
            "expected ERC20-related finding, got: {}",
            vuln_type
        );
    }

    #[test]
    fn detector_dangerous_delegatecall_finds_user_controlled_target() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function execute(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_dangerous_delegatecall(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "delegatecall detector should find user-controlled target"
        );
        assert_eq!(findings[0].vulnerability_type, "Dangerous Delegatecall");
    }

    #[test]
    fn detector_unchecked_call_finds_call_without_assignment() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function forward(address payable to) public {
        to.call{value: address(this).balance}("");
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_unchecked_calls(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "unchecked call detector should find .call without return check"
        );
        assert_eq!(findings[0].vulnerability_type, "Unchecked Call");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn detector_integer_overflow_flags_unchecked_block() {
        let source = r#"
pragma solidity ^0.7.0;
contract C {
    function sub(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            return a - b;
        }
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_integer_overflow(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "integer overflow detector should find unchecked arithmetic in <0.8 or unchecked block"
        );
        assert_eq!(findings[0].vulnerability_type, "Integer Overflow/Underflow");
    }

    #[test]
    fn detector_no_false_positive_on_self_service_withdraw() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) public balances;
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amt}("");
        require(ok);
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_access_control(&tree, source, &mut findings);
        assert!(
            findings.is_empty(),
            "access control should not flag self-service withdraw (operates on msg.sender only)"
        );
    }

    // ========== Integration test: full scan on comprehensive contract ==========

    #[test]
    fn integration_scan_comprehensive_vulnerabilities_finds_multiple_types() {
        let path = "contracts/comprehensive-vulnerabilities.sol";
        let path_alt = "../contracts/comprehensive-vulnerabilities.sol";
        let path_used = if std::path::Path::new(path).exists() {
            path
        } else {
            path_alt
        };
        let findings = scan_file_with(path_used, run_all_detectors);
        assert!(
            findings.len() >= 5,
            "comprehensive-vulnerabilities.sol should yield at least 5 findings (got {}). Run from core/ with contracts/ present.",
            findings.len()
        );
        let types: std::collections::HashSet<_> = findings
            .iter()
            .map(|f| f.vulnerability_type.as_str())
            .collect();
        assert!(
            types.contains("Reentrancy"),
            "expected Reentrancy in findings: {:?}",
            types
        );
        assert!(
            types.contains("tx.origin Authentication"),
            "expected tx.origin in findings: {:?}",
            types
        );
        assert!(
            types.contains("Missing Access Control") || types.contains("Dangerous Delegatecall"),
            "expected access control or delegatecall: {:?}",
            types
        );
    }

    // ========== Suppression: stealth-ignore and baseline ==========

    #[test]
    fn suppression_parse_stealth_ignores() {
        let source = r#"
// stealth-ignore: reentrancy
        (bool ok,) = msg.sender.call{value: 1}("");
// stealth-ignore: tx.origin
        require(tx.origin == owner);
// stealth-ignore: reentrancy L20
"#;
        let ignores = parse_stealth_ignores(source);
        assert!(!ignores.is_empty());
        // Line 2 has comment -> suppresses line 2 and 3
        assert!(ignores
            .iter()
            .any(|(l, t)| *l == 2 && t.as_deref() == Some("reentrancy")));
        assert!(ignores
            .iter()
            .any(|(l, t)| *l == 3 && t.as_deref() == Some("reentrancy")));
        // Line 5 has comment -> suppresses line 5 and 6 (type stored as normalized "tx.origin")
        assert!(ignores
            .iter()
            .any(|(l, t)| *l == 5 && t.as_deref() == Some("tx.origin")));
        // L20 targets line 20 only
        assert!(ignores
            .iter()
            .any(|(l, t)| *l == 20 && t.as_deref() == Some("reentrancy")));
    }

    #[test]
    fn suppression_inline_ignores_finding() {
        // The comment must be on or just above the line the detector reports (the .call line).
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        // stealth-ignore: reentrancy
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;
        let tree = parse_solidity(source);
        let mut findings = Vec::new();
        detect_reentrancy(&tree, source, &mut findings);
        assert!(
            !findings.is_empty(),
            "reentrancy should be found without filter"
        );
        let filtered = filter_findings_by_inline_ignores(findings, source);
        assert!(
            filtered.is_empty(),
            "finding should be suppressed by // stealth-ignore: reentrancy on line above"
        );
    }

    #[test]
    fn suppression_baseline_filters_known_findings() {
        let baseline_json = r#"{"findings":[{"severity":"High","confidence":"High","line":5,"vulnerability_type":"Reentrancy","message":"","suggestion":"","file":"x.sol"}],"statistics":{"critical":0,"high":1,"medium":0,"low":0,"confidence_high":1,"confidence_medium":0,"confidence_low":0}}"#;
        let baseline: BaselineFile = serde_json::from_str(baseline_json).expect("parse");
        let set: HashSet<_> = baseline
            .findings
            .into_iter()
            .map(|f| {
                (
                    f.file.unwrap_or_default(),
                    f.line as usize,
                    normalize_vuln_type(&f.vulnerability_type),
                )
            })
            .collect();
        let finding = Finding {
            severity: Severity::High,
            confidence: Confidence::High,
            line: 5,
            vulnerability_type: "Reentrancy".to_string(),
            message: String::new(),
            suggestion: String::new(),
            file: Some("x.sol".to_string()),
        };
        let findings = vec![finding];
        let filtered = filter_findings_by_baseline(findings, &set);
        assert!(
            filtered.is_empty(),
            "finding in baseline should be filtered out"
        );
    }
}
