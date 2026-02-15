//! Security detectors for Solidity smart contracts.
//!
//! Each sub-module implements one detector category. The top-level
//! [`run_all_detectors`] function invokes every detector against a parsed
//! tree-sitter tree and collects findings into a single `Vec<Finding>`.

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

use crate::types::Finding;

/// Run every detector against a parsed Solidity AST and append findings.
pub fn run_all_detectors(
    tree: &tree_sitter::Tree,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    detect_reentrancy(tree, source, findings);
    detect_unchecked_calls(tree, source, findings);
    detect_tx_origin(tree, source, findings);
    detect_access_control(tree, source, findings);
    detect_dangerous_delegatecall(tree, source, findings);
    detect_timestamp_dependence(tree, source, findings);
    detect_unsafe_random(tree, source, findings);
    detect_integer_overflow(tree, source, findings);
    detect_flash_loan_vulnerability(tree, source, findings);
    detect_storage_collision(tree, source, findings);
    detect_front_running(tree, source, findings);
    detect_dos_loops(tree, source, findings);
    detect_unchecked_erc20(tree, source, findings);
}
