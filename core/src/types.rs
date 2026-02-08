//! Core types: severity, confidence, visibility, findings, statistics.

use colored::*;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_colored_str(&self) -> ColoredString {
        match self {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".blue(),
        }
    }

    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "High",
            Confidence::Medium => "Medium",
            Confidence::Low => "Low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Visibility {
    Public,
    External,
    Internal,
    Private,
}

impl Visibility {
    #[allow(dead_code)]
    pub fn risk_level(&self) -> u8 {
        match self {
            Visibility::External => 3,
            Visibility::Public => 3,
            Visibility::Internal => 1,
            Visibility::Private => 0,
        }
    }

    pub fn is_externally_callable(&self) -> bool {
        matches!(self, Visibility::Public | Visibility::External)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::External => "external",
            Visibility::Internal => "internal",
            Visibility::Private => "private",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub confidence: Confidence,
    pub line: usize,
    pub vulnerability_type: String,
    pub message: String,
    pub suggestion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

impl Finding {
    pub fn print(&self) {
        println!(
            "[{}] {} at line {} (Confidence: {})",
            self.severity.as_colored_str(),
            self.vulnerability_type.bold(),
            self.line,
            self.confidence.as_str().dimmed()
        );
        println!("  {} {}", "→".cyan(), self.message);
        println!("  {} {}", "Fix:".green().bold(), self.suggestion);
        println!();
    }
}

#[derive(Default, Serialize)]
pub struct Statistics {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub confidence_high: u32,
    pub confidence_medium: u32,
    pub confidence_low: u32,
}
