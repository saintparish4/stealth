//! Output formatting: terminal, JSON, and SARIF 2.1.0.

use crate::types::{Finding, Severity, Statistics};
use colored::*;
use serde::Serialize;
use std::collections::BTreeMap;

pub fn print_results(path: &str, findings: &[Finding], stats: &Statistics) {
    println!("\n{}", "═".repeat(60).dimmed());
    println!("{}", "Stealth Security Scan Results".bold().underline());
    println!("{}", "═".repeat(60).dimmed());
    println!("{} {}\n", "Scanning:".bold(), path);

    if findings.is_empty() {
        println!("{}", "✓ No vulnerabilities found!".green().bold());
    } else {
        println!(
            "{} {} vulnerabilities found:\n",
            "⚠".yellow(),
            findings.len()
        );

        for finding in findings {
            finding.print();
        }

        println!("{}", "─".repeat(60).dimmed());
        println!("{}", "Summary".bold());
        if stats.critical > 0 {
            println!("  {} Critical: {}", "●".red(), stats.critical);
        }
        if stats.high > 0 {
            println!("  {} High: {}", "●".red(), stats.high);
        }
        if stats.medium > 0 {
            println!("  {} Medium: {}", "●".yellow(), stats.medium);
        }
        if stats.low > 0 {
            println!("  {} Low: {}", "●".blue(), stats.low);
        }
    }
    println!();
}

pub fn print_json(findings: &[Finding], stats: &Statistics) {
    #[derive(Serialize)]
    struct Output<'a> {
        findings: &'a [Finding],
        statistics: &'a Statistics,
    }

    let output = Output {
        findings,
        statistics: stats,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

// ============================================================================
// SARIF 2.1.0 Output
// ============================================================================

/// SARIF 2.1.0 severity levels.
/// Maps Stealth severity to SARIF `level` values.
fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Derive a stable, kebab-case rule ID from the vulnerability type string.
/// e.g. "tx.origin Authentication" -> "tx-origin-authentication"
fn rule_id_from_vuln_type(vuln_type: &str) -> String {
    vuln_type
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        // collapse consecutive dashes and trim edges
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Default severity tag for SARIF rule properties (used for GitHub Code Scanning).
fn severity_tag(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

// -- SARIF schema structs (only the subset we need) --------------------------

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    default_configuration: SarifDefaultConfiguration,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifDefaultConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    tags: Vec<&'static str>,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    #[serde(rename = "ruleIndex")]
    rule_index: usize,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
}

/// Print findings as SARIF 2.1.0 JSON to stdout.
///
/// Produces a single `run` with one `result` per finding. Rules are
/// deduplicated: each unique vulnerability type becomes one entry in
/// `tool.driver.rules`, and results reference it by `ruleIndex`.
///
/// This output is compatible with GitHub Code Scanning's
/// `github/codeql-action/upload-sarif` action.
pub fn print_sarif(findings: &[Finding]) {
    // Build deduplicated rules list, preserving insertion order via BTreeMap
    // keyed on rule_id so output is deterministic.
    let mut rule_map: BTreeMap<String, (usize, SarifRule)> = BTreeMap::new();

    for f in findings {
        let id = rule_id_from_vuln_type(&f.vulnerability_type);
        if !rule_map.contains_key(&id) {
            let idx = rule_map.len();
            rule_map.insert(
                id.clone(),
                (
                    idx,
                    SarifRule {
                        id: id.clone(),
                        name: f.vulnerability_type.clone(),
                        short_description: SarifMessage {
                            text: format!("Stealth: {} detection", f.vulnerability_type),
                        },
                        default_configuration: SarifDefaultConfiguration {
                            level: sarif_level(&f.severity),
                        },
                        properties: SarifRuleProperties {
                            tags: vec!["security", severity_tag(&f.severity)],
                        },
                    },
                ),
            );
        }
    }

    // Build the ordered rules vec and a quick index lookup.
    let mut rules: Vec<(String, usize, SarifRule)> = rule_map
        .into_iter()
        .map(|(id, (idx, rule))| (id, idx, rule))
        .collect();
    rules.sort_by_key(|(_, idx, _)| *idx);

    let index_of: BTreeMap<String, usize> = rules
        .iter()
        .enumerate()
        .map(|(pos, (id, _, _))| (id.clone(), pos))
        .collect();

    let sarif_rules: Vec<SarifRule> = rules.into_iter().map(|(_, _, r)| r).collect();

    // Build results.
    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let id = rule_id_from_vuln_type(&f.vulnerability_type);
            let rule_index = index_of.get(&id).copied().unwrap_or(0);

            // Combine message + suggestion into the SARIF result message.
            let text = if f.suggestion.is_empty() {
                f.message.clone()
            } else {
                format!("{} Fix: {}", f.message, f.suggestion)
            };

            let uri = f
                .file
                .as_deref()
                .unwrap_or("unknown")
                .replace('\\', "/");

            SarifResult {
                rule_id: id,
                rule_index,
                level: sarif_level(&f.severity),
                message: SarifMessage { text },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri },
                        region: SarifRegion {
                            start_line: f.line,
                        },
                    },
                }],
            }
        })
        .collect();

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Stealth",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/saintparish4/stealth",
                    rules: sarif_rules,
                },
            },
            results,
        }],
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&log).unwrap_or_default()
    );
}
