//! Scanning: parse Solidity, run detectors (via callback), apply suppressions.

use crate::suppression;
use crate::types::{Finding, Statistics};
use colored::*;
use std::fs;
use walkdir::WalkDir;

pub fn scan_file_with<F>(file_path: &str, run_detectors: F) -> Vec<Finding>
where
    F: FnOnce(&tree_sitter::Tree, &str, &mut Vec<Finding>),
{
    let source = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Could not read '{}': {}", "Error:".red().bold(), file_path, e);
            return Vec::new();
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if let Err(e) = parser.set_language(&tree_sitter_solidity::LANGUAGE.into()) {
        eprintln!("{} Failed to load Solidity grammar: {}", "Error:".red().bold(), e);
        return Vec::new();
    }

    let tree = match parser.parse(&source, None) {
        Some(t) => t,
        None => {
            eprintln!("{} Failed to parse '{}'", "Error:".red().bold(), file_path);
            return Vec::new();
        }
    };

    let mut findings = Vec::new();
    run_detectors(&tree, &source, &mut findings);

    for f in &mut findings {
        f.file = Some(file_path.to_string());
    }

    suppression::filter_findings_by_inline_ignores(findings, &source)
}

pub fn scan_directory_with<F>(dir_path: &str, recursive: bool, run_detectors: F) -> Vec<Finding>
where
    F: Fn(&tree_sitter::Tree, &str, &mut Vec<Finding>) + Copy,
{
    let walker = if recursive { WalkDir::new(dir_path) } else { WalkDir::new(dir_path).max_depth(1) };
    let mut all = Vec::new();
    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_file() && p.extension().map_or(false, |e| e == "sol") {
            let path_str = p.to_str().unwrap_or_default();
            all.extend(scan_file_with(path_str, run_detectors));
        }
    }
    all
}

pub fn calculate_statistics(findings: &[Finding]) -> Statistics {
    let mut stats = Statistics::default();

    for finding in findings {
        match finding.severity {
            crate::types::Severity::Critical => stats.critical += 1,
            crate::types::Severity::High => stats.high += 1,
            crate::types::Severity::Medium => stats.medium += 1,
            crate::types::Severity::Low => stats.low += 1,
        }
        match finding.confidence {
            crate::types::Confidence::High => stats.confidence_high += 1,
            crate::types::Confidence::Medium => stats.confidence_medium += 1,
            crate::types::Confidence::Low => stats.confidence_low += 1,
        }
    }

    stats
}
