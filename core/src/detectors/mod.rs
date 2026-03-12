//! Security detectors for Solidity smart contracts.
//!
//! Each sub-module implements one detector as a zero-sized struct implementing
//! the [`Detector`] trait (defined in [`crate::detector_trait`]).
//!
//! A [`DetectorRegistry`] is built once at startup via [`build_registry`] and
//! passed to the scan functions.
//!
//! # Adding a new detector
//!
//! 1. Create `core/src/detectors/my_detector.rs` with a struct + `impl Detector`.
//! 2. Declare `mod my_detector` and `pub use` the struct below.
//! 3. Register it in [`build_registry`].

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

pub use access_control::AccessControlDetector;
pub use delegatecall::DangerousDelegatecallDetector;
pub use dos_loops::DosLoopsDetector;
pub use flash_loan::FlashLoanDetector;
pub use front_running::FrontRunningDetector;
pub use integer_overflow::IntegerOverflowDetector;
pub use reentrancy::ReentrancyDetector;
pub use storage_collision::StorageCollisionDetector;
pub use timestamp::TimestampDetector;
pub use tx_origin::TxOriginDetector;
pub use unchecked_calls::UncheckedCallsDetector;
pub use unchecked_erc20::UncheckedErc20Detector;
pub use unsafe_random::UnsafeRandomDetector;

use crate::detector_trait::DetectorRegistry;

// ---------------------------------------------------------------------------
// Registry construction
// ---------------------------------------------------------------------------

/// Build a [`DetectorRegistry`] containing all 13 detectors in canonical order.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector_trait::AnalysisContext;
    use crate::scan::new_solidity_parser;
    use crate::types::Finding;
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
            assert!(
                !id.is_empty(),
                "detector '{}' has an empty id",
                detector.name()
            );
            assert!(seen.insert(id), "duplicate detector id: '{}'", id);
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

    /// Registry should produce findings on the comprehensive-vulnerabilities contract.
    #[test]
    fn registry_produces_findings_on_comprehensive_contract() {
        let source = include_str!("../../contracts/comprehensive-vulnerabilities.sol");
        let mut parser = new_solidity_parser().expect("failed to build parser");
        let tree = parser.parse(source, None).expect("failed to parse");

        let mut findings: Vec<Finding> = Vec::new();
        let ctx = AnalysisContext::new(&tree, source);
        build_registry().run_all(&ctx, &mut findings);

        assert!(
            !findings.is_empty(),
            "expected at least one finding on comprehensive-vulnerabilities.sol"
        );
    }
}
