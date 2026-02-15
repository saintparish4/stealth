//! Stealth - Smart Contract Security Scanner (library).
//!
//! Modules: types, helpers, suppression, output, scan, detectors.
//! Use `scan_file_with` / `scan_directory_with` with `detectors::run_all_detectors`
//! or invoke individual `detect_*` functions directly.

pub mod detectors;
pub mod helpers;
pub mod output;
pub mod scan;
pub mod suppression;
pub mod types;

pub use helpers::*;
pub use output::{print_json, print_results};
pub use scan::{calculate_statistics, scan_directory_with, scan_file_with};
pub use suppression::{
    filter_findings_by_baseline, filter_findings_by_inline_ignores, load_baseline, parse_stealth_ignores,
    BaselineFile,
};
pub use types::{Confidence, Finding, Severity, Statistics, Visibility};
