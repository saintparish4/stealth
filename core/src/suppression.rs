//! Inline suppressions (// stealth-ignore:) and baseline filtering.

use crate::helpers::normalize_vuln_type;
use crate::types::Finding;
use colored::*;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;

/// Parsed inline suppression: (line number that is suppressed, optional vulnerability type).
/// Comment on line N applies to line N and N+1 (comment above code suppresses next line).
/// Format: // stealth-ignore: [type] [L<line>]
pub fn parse_stealth_ignores(source: &str) -> Vec<(usize, Option<String>)> {
    let mut result = Vec::new();
    for (zero_based, line) in source.lines().enumerate() {
        let line_no = zero_based + 1;
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("//") else {
            continue;
        };
        let rest = rest.trim();
        let Some(rest) = rest.strip_prefix("stealth-ignore:") else {
            continue;
        };
        let rest = rest.trim();
        let words: Vec<&str> = rest.split_ascii_whitespace().collect();
        let (type_opt, target_line_opt) = if words.is_empty() {
            (None, None)
        } else {
            let mut target_line_opt: Option<usize> = None;
            let mut type_opt: Option<String> = None;
            for w in &words {
                if w.starts_with('L') && w.len() > 1 && w[1..].chars().all(|c| c.is_ascii_digit()) {
                    target_line_opt = w[1..].parse().ok();
                } else if type_opt.is_none() {
                    type_opt = Some(normalize_vuln_type(w));
                }
            }
            (type_opt, target_line_opt)
        };
        if let Some(target_line) = target_line_opt {
            result.push((target_line, type_opt));
        } else {
            result.push((line_no, type_opt.clone()));
            result.push((line_no + 1, type_opt));
        }
    }
    result
}

/// Returns true if this finding is suppressed by an inline stealth-ignore comment.
fn is_suppressed_by_inline(finding: &Finding, source: &str) -> bool {
    let ignores = parse_stealth_ignores(source);
    let line = finding.line;
    let type_norm = normalize_vuln_type(&finding.vulnerability_type);
    for (ignored_line, type_opt) in &ignores {
        if *ignored_line != line {
            continue;
        }
        match type_opt {
            None => return true,
            Some(t) if t.is_empty() => return true,
            Some(t) if normalize_vuln_type(t) == type_norm => return true,
            _ => {}
        }
    }
    false
}

/// Filter out findings that are suppressed by // stealth-ignore: in the source.
pub fn filter_findings_by_inline_ignores(findings: Vec<Finding>, source: &str) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| !is_suppressed_by_inline(f, source))
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct BaselineFinding {
    #[serde(default)]
    pub file: Option<String>,
    pub line: u64,
    #[serde(rename = "vulnerability_type")]
    pub vulnerability_type: String,
}

#[derive(Debug, Deserialize)]
pub struct BaselineFile {
    pub findings: Vec<BaselineFinding>,
}

/// Load baseline from JSON (same format as scanner output). Returns set of (file, line, type_norm).
pub fn load_baseline(path: &str) -> HashSet<(String, usize, String)> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Could not read baseline file '{}': {}",
                "Error:".red().bold(),
                path,
                e
            );
            return HashSet::new();
        }
    };
    let baseline: BaselineFile = match serde_json::from_str(&content) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "{} Invalid baseline JSON in '{}': {}",
                "Error:".red().bold(),
                path,
                e
            );
            return HashSet::new();
        }
    };
    baseline
        .findings
        .into_iter()
        .map(|f| {
            let file = f.file.unwrap_or_default();
            let line = f.line as usize;
            let typ = normalize_vuln_type(&f.vulnerability_type);
            (file, line, typ)
        })
        .collect()
}

/// Filter to findings not in baseline (only "new" findings).
pub fn filter_findings_by_baseline(
    findings: Vec<Finding>,
    baseline_set: &HashSet<(String, usize, String)>,
) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| {
            let file = f.file.as_deref().unwrap_or("");
            let key = (
                file.to_string(),
                f.line,
                normalize_vuln_type(&f.vulnerability_type),
            );
            !baseline_set.contains(&key)
        })
        .collect()
}
