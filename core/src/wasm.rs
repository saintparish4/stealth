//! WASM entry point: exposes `scan_source` for use from JavaScript.
//!
//! Built with: wasm-pack build --target web --features wasm --no-default-features
//! Consumers call `scan_source(solidityCode)` and receive a JSON string
//! containing an array of Finding objects.

use wasm_bindgen::prelude::*;

use crate::detectors::run_all_detectors;
use crate::suppression::filter_findings_by_inline_ignores;
use crate::types::Finding;

/// Called automatically when the WASM module is instantiated.
/// Sets up a panic hook so Rust panics surface as readable console errors
/// instead of opaque "unreachable" messages.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Scan Solidity source code and return findings as a JSON string.
///
/// Returns `"[]"` on parse failure rather than panicking, so the caller
/// always receives valid JSON.
///
/// # Example (JavaScript)
/// ```js
/// import init, { scan_source } from './stealth_scanner';
///
/// await init();                       // load WASM
/// const json = scan_source(code);     // scan
/// const findings = JSON.parse(json);  // use
/// ```
#[wasm_bindgen]
pub fn scan_source(source: &str) -> String {
    let mut parser = tree_sitter::Parser::new();

    if parser
        .set_language(&tree_sitter_solidity::LANGUAGE.into())
        .is_err()
    {
        return "[]".to_string();
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return "[]".to_string(),
    };

    let mut findings: Vec<Finding> = Vec::new();
    run_all_detectors(&tree, source, &mut findings);

    // Apply inline suppressions (// stealth-ignore: ...)
    let findings = filter_findings_by_inline_ignores(findings, source);

    serde_json::to_string(&findings).unwrap_or_else(|_| "[]".to_string())
}
