//! Trust-anchor detector tests: lock in correct behavior for the six highest-impact detectors.
//!
//! Each detector has two guarantees:
//! - **Must report**: a known-vulnerable snippet produces at least one finding for that detector.
//! - **Must not report**: a known-safe snippet produces zero findings for that detector.
//!
//! These tests fail if detector logic is mutated (e.g. operator flip, stub return), so they
//! directly improve mutation score and user trust.

use stealth_scanner::detectors::build_registry;
use stealth_scanner::scan::new_solidity_parser;
use stealth_scanner::suppression::filter_findings_by_inline_ignores;
use stealth_scanner::types::Finding;
use stealth_scanner::AnalysisContext;

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

fn count_by_detector(findings: &[Finding], detector_id: &str) -> usize {
    findings
        .iter()
        .filter(|f| f.detector_id == detector_id)
        .count()
}

// ---------------------------------------------------------------------------
// 1. Reentrancy
// ---------------------------------------------------------------------------

#[test]
fn reentrancy_must_report_on_vulnerable() {
    let source = r#"
pragma solidity ^0.8.0;
contract Vuln {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "reentrancy");
    assert!(
        n >= 1,
        "reentrancy detector must report on call-before-state-write; got {} findings",
        n
    );
}

#[test]
fn reentrancy_must_not_report_on_safe() {
    let source = r#"
pragma solidity ^0.8.0;
contract Safe {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "reentrancy");
    assert_eq!(
        n, 0,
        "reentrancy detector must not report on CEI pattern; got {} findings",
        n
    );
}

// ---------------------------------------------------------------------------
// 2. Access control
// ---------------------------------------------------------------------------

#[test]
fn access_control_must_report_on_vulnerable() {
    let source = r#"
pragma solidity ^0.8.0;
contract Vuln {
    address public owner;
    constructor() { owner = msg.sender; }
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "access-control");
    assert!(
        n >= 1,
        "access-control detector must report on unguarded selfdestruct; got {} findings",
        n
    );
}

#[test]
fn access_control_must_not_report_on_safe() {
    let source = r#"
pragma solidity ^0.8.0;
contract Safe {
    address public owner;
    constructor() { owner = msg.sender; }
    function destroy() public {
        require(msg.sender == owner);
        selfdestruct(payable(owner));
    }
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "access-control");
    assert_eq!(
        n, 0,
        "access-control detector must not report when owner check present; got {} findings",
        n
    );
}

// ---------------------------------------------------------------------------
// 3. Unchecked calls
// ---------------------------------------------------------------------------

#[test]
fn unchecked_calls_must_report_on_vulnerable() {
    let source = r#"
pragma solidity ^0.8.0;
contract Vuln {
    address owner;
    constructor() { owner = msg.sender; }
    function forward(address payable to) public {
        require(msg.sender == owner);
        to.call{value: address(this).balance}("");
    }
    receive() external payable {}
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "unchecked-calls");
    assert!(
        n >= 1,
        "unchecked-calls detector must report when return value ignored; got {} findings",
        n
    );
}

#[test]
fn unchecked_calls_must_not_report_on_safe() {
    let source = r#"
pragma solidity ^0.8.0;
contract Safe {
    address owner;
    constructor() { owner = msg.sender; }
    function forward(address payable to) public {
        require(msg.sender == owner);
        (bool success,) = to.call{value: address(this).balance}("");
        require(success);
    }
    receive() external payable {}
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "unchecked-calls");
    assert_eq!(
        n, 0,
        "unchecked-calls detector must not report when return checked; got {} findings",
        n
    );
}

// ---------------------------------------------------------------------------
// 4. Unchecked ERC20
// ---------------------------------------------------------------------------

#[test]
fn unchecked_erc20_must_report_on_vulnerable() {
    let source = r#"
pragma solidity ^0.8.0;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
contract Vuln {
    function pay(address token, address to, uint256 amt) public {
        IERC20(token).transfer(to, amt);
    }
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "unchecked-erc20");
    assert!(
        n >= 1,
        "unchecked-erc20 detector must report on unchecked transfer(); got {} findings",
        n
    );
}

#[test]
fn unchecked_erc20_must_not_report_on_safe() {
    let source = r#"
pragma solidity ^0.8.0;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
contract Safe {
    function pay(address token, address to, uint256 amt) public {
        require(IERC20(token).transfer(to, amt), "transfer failed");
    }
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "unchecked-erc20");
    assert_eq!(
        n, 0,
        "unchecked-erc20 detector must not report when return checked; got {} findings",
        n
    );
}

// ---------------------------------------------------------------------------
// 5. Tx.origin
// ---------------------------------------------------------------------------

#[test]
fn tx_origin_must_report_on_vulnerable() {
    let source = r#"
pragma solidity ^0.8.0;
contract Vuln {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdraw() public {
        require(tx.origin == owner);
        payable(owner).transfer(address(this).balance);
    }
    receive() external payable {}
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "tx-origin");
    assert!(
        n >= 1,
        "tx-origin detector must report when tx.origin used for auth; got {} findings",
        n
    );
}

#[test]
fn tx_origin_must_not_report_on_safe() {
    let source = r#"
pragma solidity ^0.8.0;
contract Safe {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdraw() public {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
    receive() external payable {}
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "tx-origin");
    assert_eq!(
        n, 0,
        "tx-origin detector must not report when msg.sender used; got {} findings",
        n
    );
}

// ---------------------------------------------------------------------------
// 6. Dangerous delegatecall
// ---------------------------------------------------------------------------

#[test]
fn dangerous_delegatecall_must_report_on_vulnerable() {
    let source = r#"
pragma solidity ^0.8.0;
contract Vuln {
    function execute(address target, bytes memory data) public {
        (bool ok,) = target.delegatecall(data);
        require(ok);
    }
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "dangerous-delegatecall");
    assert!(n >= 1, "dangerous-delegatecall detector must report on user-controlled delegatecall; got {} findings", n);
}

#[test]
fn dangerous_delegatecall_must_not_report_on_safe() {
    let source = r#"
pragma solidity ^0.8.0;
contract Safe {
    address public immutable trustedLibrary;
    constructor(address _lib) { trustedLibrary = _lib; }
    function execute(bytes memory data) public {
        (bool ok,) = trustedLibrary.delegatecall(data);
        require(ok);
    }
}
"#;
    let findings = scan_source(source);
    let n = count_by_detector(&findings, "dangerous-delegatecall");
    assert_eq!(n, 0, "dangerous-delegatecall detector must not report on immutable trusted delegatecall; got {} findings", n);
}
