//! Stealth - Smart Contract Security Scanner (library).
//!
//! Modules: types, helpers, suppression, detectors, scan, output (always available).
//! Module:  lsp (LSP-only — requires `lsp` feature).
//! Module:  wasm (WASM-only — requires `wasm` feature).

pub mod detector_trait;
pub mod detectors;
pub mod helpers;
pub mod output;
pub mod scan;
pub mod suppression;
pub mod types;

#[cfg(feature = "lsp")]
pub mod lsp;
#[cfg(feature = "wasm")]
pub mod wasm;

// --- Re-exports (always available) ------------------------------------------

pub use detector_trait::{AnalysisContext, Detector, DetectorRegistry};
pub use helpers::*;
pub use output::{format_json, format_sarif};
pub use scan::{calculate_statistics, scan_directory_with, scan_file_with};
pub use suppression::{
    filter_findings_by_baseline, filter_findings_by_inline_ignores, load_baseline,
    parse_stealth_ignores, BaselineFile,
};
pub use types::{
    Confidence, Finding, ScanError, ScanErrorKind, ScanOutcome, Severity, Statistics, Visibility,
};

// --- Re-exports (CLI-only) --------------------------------------------------

#[cfg(feature = "cli")]
pub use output::{format_terminal, print_json, print_results, print_sarif};
