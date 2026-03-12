//! Security detectors for Solidity smart contracts.
//!
//! Each sub-module implements one detector category.
//!
//! # Architecture
//!
//! Every detector is a zero-sized struct implementing the [`Detector`] trait
//! (defined in [`crate::detector_trait`]).  A [`DetectorRegistry`] is built
//! once at startup via [`build_registry`] and shared for the lifetime of the
//! process.
//!
//! [`run_all_detectors`] is a backward-compatible shim; it constructs an
//! [`AnalysisContext`] and delegates to the global registry.  All call sites
//! that already use `run_all_detectors` continue to work without modification.
//!
//! # Adding a new detector
//!
//! 1. Create `core/src/detectors/my_detector.rs` with a `detect_my_thing` function.
//! 2. Declare `mod my_detector` and `pub use` it below.
//! 3. Add a zero-sized `struct MyDetector` that implements [`Detector`].
//! 4. Register it in [`build_registry`].

mod access_control;
mod delegatecall;
mod dos_loops;
mod flash_loan;
mod front_running;
mod integer_overflow;
mod reentrancy;
mod storage_collision;
mod timestamp;
mod tx_origin;
mod unchecked_calls;
mod unchecked_erc20;
mod unsafe_random;

pub use access_control::detect_access_control;
pub use delegatecall::detect_dangerous_delegatecall;
pub use dos_loops::detect_dos_loops;
pub use flash_loan::detect_flash_loan_vulnerability;
pub use front_running::detect_front_running;
pub use integer_overflow::detect_integer_overflow;
pub use reentrancy::detect_reentrancy;
pub use storage_collision::detect_storage_collision;
pub use timestamp::detect_timestamp_dependence;
pub use tx_origin::detect_tx_origin;
pub use unchecked_calls::detect_unchecked_calls;
pub use unchecked_erc20::detect_unchecked_erc20;
pub use unsafe_random::detect_unsafe_random;

use crate::detector_trait::{AnalysisContext, Detector, DetectorRegistry};
use crate::types::{Finding, Severity};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Detector structs (zero-sized; runtime cost = vtable lookup only)
// ---------------------------------------------------------------------------
//
// Phase S1: All 12 non-tx-origin detectors are shims that delegate to the
// existing detect_* functions.  The TxOriginDetector is the proof-of-concept
// for the full trait-based approach (Phase S2 will rewrite the inner logic to
// use pure AST traversal).
//
// Phase S2 will replace each shim's `run` body with direct AST analysis,
// at which point the legacy `detect_*` functions can be removed.

struct ReentrancyDetector;
impl Detector for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "reentrancy"
    }
    fn name(&self) -> &'static str {
        "Reentrancy"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC02:2025 - Reentrancy Attacks")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_reentrancy(ctx.tree, ctx.source, findings);
    }
}

struct UncheckedCallsDetector;
impl Detector for UncheckedCallsDetector {
    fn id(&self) -> &'static str {
        "unchecked-calls"
    }
    fn name(&self) -> &'static str {
        "Unchecked External Call Return Values"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC04:2025 - Lack of Input Validation")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_unchecked_calls(ctx.tree, ctx.source, findings);
    }
}

/// Proof-of-concept: first detector fully migrated to the trait architecture.
///
/// The inner `detect_tx_origin` function still performs the detection; Phase S2
/// will replace it with pure `member_expression` AST node traversal and remove
/// the string-matching fallback.
struct TxOriginDetector;
impl Detector for TxOriginDetector {
    fn id(&self) -> &'static str {
        "tx-origin"
    }
    fn name(&self) -> &'static str {
        "tx.origin Authentication"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC01:2025 - Access Control Vulnerabilities")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_tx_origin(ctx.tree, ctx.source, findings);
    }
}

struct AccessControlDetector;
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
        detect_access_control(ctx.tree, ctx.source, findings);
    }
}

struct DangerousDelegatecallDetector;
impl Detector for DangerousDelegatecallDetector {
    fn id(&self) -> &'static str {
        "dangerous-delegatecall"
    }
    fn name(&self) -> &'static str {
        "Dangerous Delegatecall"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC01:2025 - Access Control Vulnerabilities")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_dangerous_delegatecall(ctx.tree, ctx.source, findings);
    }
}

struct TimestampDetector;
impl Detector for TimestampDetector {
    fn id(&self) -> &'static str {
        "timestamp-dependence"
    }
    fn name(&self) -> &'static str {
        "Timestamp Dependence"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC06:2025 - Unsafe Randomness and Predictability")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_timestamp_dependence(ctx.tree, ctx.source, findings);
    }
}

struct UnsafeRandomDetector;
impl Detector for UnsafeRandomDetector {
    fn id(&self) -> &'static str {
        "unsafe-random"
    }
    fn name(&self) -> &'static str {
        "Unsafe Randomness"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC06:2025 - Unsafe Randomness and Predictability")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_unsafe_random(ctx.tree, ctx.source, findings);
    }
}

struct IntegerOverflowDetector;
impl Detector for IntegerOverflowDetector {
    fn id(&self) -> &'static str {
        "integer-overflow"
    }
    fn name(&self) -> &'static str {
        "Integer Overflow / Underflow"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC03:2025 - Integer Overflow and Underflow")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_integer_overflow(ctx.tree, ctx.source, findings);
    }
}

struct FlashLoanDetector;
impl Detector for FlashLoanDetector {
    fn id(&self) -> &'static str {
        "flash-loan"
    }
    fn name(&self) -> &'static str {
        "Flash Loan Vulnerability"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC07:2025 - Flash Loan Attacks")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_flash_loan_vulnerability(ctx.tree, ctx.source, findings);
    }
}

struct StorageCollisionDetector;
impl Detector for StorageCollisionDetector {
    fn id(&self) -> &'static str {
        "storage-collision"
    }
    fn name(&self) -> &'static str {
        "Storage Collision"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC08:2025 - Insecure Smart Contract Composition")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_storage_collision(ctx.tree, ctx.source, findings);
    }
}

struct FrontRunningDetector;
impl Detector for FrontRunningDetector {
    fn id(&self) -> &'static str {
        "front-running"
    }
    fn name(&self) -> &'static str {
        "Front-Running Vulnerability"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC09:2025 - Denial of Service (DoS) Attacks")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_front_running(ctx.tree, ctx.source, findings);
    }
}

struct DosLoopsDetector;
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
        detect_dos_loops(ctx.tree, ctx.source, findings);
    }
}

struct UncheckedErc20Detector;
impl Detector for UncheckedErc20Detector {
    fn id(&self) -> &'static str {
        "unchecked-erc20"
    }
    fn name(&self) -> &'static str {
        "Unchecked ERC-20 Return Values"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC04:2025 - Lack of Input Validation")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        detect_unchecked_erc20(ctx.tree, ctx.source, findings);
    }
}

// ---------------------------------------------------------------------------
// Registry construction
// ---------------------------------------------------------------------------

/// Build a [`DetectorRegistry`] containing all 13 detectors in canonical order.
///
/// The order mirrors the original `run_all_detectors` call sequence so that
/// finding lists remain stable across the refactor.
pub fn build_registry() -> DetectorRegistry {
    DetectorRegistry::new(vec![
        Box::new(ReentrancyDetector),
        Box::new(UncheckedCallsDetector),
        Box::new(TxOriginDetector),
        Box::new(AccessControlDetector),
        Box::new(DangerousDelegatecallDetector),
        Box::new(TimestampDetector),
        Box::new(UnsafeRandomDetector),
        Box::new(IntegerOverflowDetector),
        Box::new(FlashLoanDetector),
        Box::new(StorageCollisionDetector),
        Box::new(FrontRunningDetector),
        Box::new(DosLoopsDetector),
        Box::new(UncheckedErc20Detector),
    ])
}

// Global registry built once on first use.
static REGISTRY: OnceLock<DetectorRegistry> = OnceLock::new();

/// Return a reference to the process-wide detector registry.
pub fn global_registry() -> &'static DetectorRegistry {
    REGISTRY.get_or_init(build_registry)
}

// ---------------------------------------------------------------------------
// Backward-compatible entry point
// ---------------------------------------------------------------------------

/// Run every detector against a parsed Solidity AST and append findings.
///
/// This function maintains the same signature as before the trait refactor.
/// Internally it delegates to the global [`DetectorRegistry`].
pub fn run_all_detectors(tree: &tree_sitter::Tree, source: &str, findings: &mut Vec<Finding>) {
    let ctx = AnalysisContext::new(tree, source);
    global_registry().run_all(&ctx, findings);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::new_solidity_parser;
    use std::collections::HashSet;

    /// The registry must contain exactly 13 detectors — one per vulnerability category.
    #[test]
    fn registry_has_thirteen_detectors() {
        let registry = build_registry();
        assert_eq!(
            registry.len(),
            13,
            "expected 13 detectors, got {}",
            registry.len()
        );
    }

    /// Every detector must have a unique, non-empty kebab-case id.
    #[test]
    fn detector_ids_are_unique_and_non_empty() {
        let registry = build_registry();
        let mut seen: HashSet<&str> = HashSet::new();
        for detector in registry.detectors() {
            let id = detector.id();
            assert!(!id.is_empty(), "detector '{}' has an empty id", detector.name());
            assert!(
                seen.insert(id),
                "duplicate detector id: '{}'",
                id
            );
        }
    }

    /// Every detector must have a non-empty name.
    #[test]
    fn detector_names_are_non_empty() {
        let registry = build_registry();
        for detector in registry.detectors() {
            assert!(
                !detector.name().is_empty(),
                "detector '{}' has an empty name",
                detector.id()
            );
        }
    }

    /// `run_all_detectors` (legacy shim) and `registry.run_all` must produce
    /// identical findings on the comprehensive-vulnerabilities contract.
    #[test]
    fn run_all_detectors_matches_registry_output() {
        let source = include_str!("../../contracts/comprehensive-vulnerabilities.sol");
        let mut parser = new_solidity_parser().expect("failed to build parser");
        let tree = parser.parse(source, None).expect("failed to parse");

        let mut legacy_findings: Vec<Finding> = Vec::new();
        run_all_detectors(&tree, source, &mut legacy_findings);

        let mut registry_findings: Vec<Finding> = Vec::new();
        let ctx = AnalysisContext::new(&tree, source);
        build_registry().run_all(&ctx, &mut registry_findings);

        // Finding order and content must be identical.
        assert_eq!(
            legacy_findings.len(),
            registry_findings.len(),
            "finding count mismatch: legacy={}, registry={}",
            legacy_findings.len(),
            registry_findings.len()
        );

        for (i, (lf, rf)) in legacy_findings.iter().zip(registry_findings.iter()).enumerate() {
            assert_eq!(
                lf.detector_id, rf.detector_id,
                "finding[{}] detector_id mismatch",
                i
            );
            assert_eq!(lf.line, rf.line, "finding[{}] line mismatch", i);
            assert_eq!(
                lf.vulnerability_type, rf.vulnerability_type,
                "finding[{}] vulnerability_type mismatch",
                i
            );
        }
    }

    /// The global registry singleton returns the same pointer on repeated calls.
    #[test]
    fn global_registry_is_singleton() {
        let a: *const DetectorRegistry = global_registry();
        let b: *const DetectorRegistry = global_registry();
        assert_eq!(a, b, "global_registry() should return the same instance");
    }
}
