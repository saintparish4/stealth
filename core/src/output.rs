//! Output formatting: terminal and JSON.

use crate::types::{Finding, Statistics};
use colored::*;
use serde::Serialize;

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
