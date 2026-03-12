//! Detector trait, AnalysisContext, and DetectorRegistry.
//!
//! Every vulnerability detector implements the [`Detector`] trait, which gives it a
//! machine-readable `id`, a human-readable `name`, a default `severity`, and an
//! optional OWASP category. Detectors are collected in a [`DetectorRegistry`] that is
//! built once at startup and shared for the lifetime of the process.
//!
//! [`AnalysisContext`] is the read-only bundle passed to each [`Detector::run`] call.
//! Phase S3 will extend it with an optional control flow graph.

use crate::types::{Finding, Severity};
use tree_sitter::Tree;

// ---------------------------------------------------------------------------
// AnalysisContext
// ---------------------------------------------------------------------------

/// Everything a detector needs to analyse one Solidity file.
///
/// Passed by reference to [`Detector::run`]; detectors only read from it.
/// Phase S3 will add `pub cfg: Option<&'a ControlFlowGraph>` here without
/// requiring changes to existing detectors.
pub struct AnalysisContext<'a> {
    /// The fully parsed tree-sitter syntax tree for the file.
    pub tree: &'a Tree,
    /// Raw Solidity source bytes (UTF-8).
    pub source: &'a str,
    /// Path to the file being analysed, if known.
    pub file_path: Option<&'a str>,
}

impl<'a> AnalysisContext<'a> {
    /// Construct a context from the minimal required fields.
    pub fn new(tree: &'a Tree, source: &'a str) -> Self {
        Self {
            tree,
            source,
            file_path: None,
        }
    }

    /// Attach a file path (used for file-scoped analyses and error messages).
    pub fn with_file_path(mut self, path: &'a str) -> Self {
        self.file_path = Some(path);
        self
    }
}

// ---------------------------------------------------------------------------
// Detector trait
// ---------------------------------------------------------------------------

/// A self-describing vulnerability detector.
///
/// Implementations are zero-sized structs; all state lives in `AnalysisContext`.
/// The trait is object-safe so detectors can be collected as `Box<dyn Detector>`.
pub trait Detector: Send + Sync {
    /// Stable, kebab-case identifier (e.g. `"reentrancy"`, `"tx-origin"`).
    /// Used in suppression rules, baselines, and CI output.
    fn id(&self) -> &'static str;

    /// Human-readable display name (e.g. `"Reentrancy"`, `"tx.origin Authentication"`).
    fn name(&self) -> &'static str;

    /// Default severity for findings emitted by this detector.
    /// Individual findings may override this when context warrants it.
    fn severity(&self) -> Severity;

    /// OWASP Smart Contract Top 10 category, if applicable.
    fn owasp_category(&self) -> Option<&'static str>;

    /// Run the detector against the provided context and append any findings.
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>);
}

// ---------------------------------------------------------------------------
// DetectorRegistry
// ---------------------------------------------------------------------------

/// An ordered collection of detectors run against every scanned file.
///
/// Build once (e.g. via [`DetectorRegistry::with_all_detectors`]) and share
/// across threads. Each entry is a heap-allocated trait object; the actual
/// detector structs are zero-sized so the only cost is the vtable pointer.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    /// Build a registry from an explicit list of detectors.
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    /// All registered detectors in run order.
    pub fn detectors(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }

    /// Number of registered detectors.
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// Returns `true` if no detectors are registered.
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Run every detector and append findings to `findings`.
    pub fn run_all(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for detector in &self.detectors {
            detector.run(ctx, findings);
        }
    }
}
