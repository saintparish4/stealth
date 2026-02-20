//! Stealth - Smart Contract Security Scanner (library).
//!
//! Modules: types, helpers, suppression, detectors (always available).
//! Modules: output, scan (CLI-only — require `cli` feature).
//! Module:  wasm (WASM-only — require `wasm` feature).

pub mod detectors;
pub mod helpers;
pub mod suppression;
pub mod types;

#[cfg(feature = "cli")]
pub mod output;
#[cfg(feature = "cli")]
pub mod scan;
#[cfg(feature = "wasm")]
pub mod wasm;
#[cfg(feature = "lsp")]
pub mod lsp;

// --- Re-exports (always available) ------------------------------------------

pub use helpers::*;
pub use suppression::{filter_findings_by_inline_ignores, parse_stealth_ignores};
pub use types::{Confidence, Finding, Severity, Statistics, Visibility};

// --- Re-exports (CLI-only) --------------------------------------------------

#[cfg(feature = "cli")]
pub use output::{print_json, print_results, print_sarif};
#[cfg(feature = "cli")]
pub use scan::{calculate_statistics, scan_directory_with, scan_file_with};
#[cfg(feature = "cli")]
pub use suppression::{filter_findings_by_baseline, load_baseline, BaselineFile};