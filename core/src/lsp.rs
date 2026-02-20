//! LSP server: exposes Stealth diagnostics over the Language Server Protocol.
//!
//! Communicates via stdio. The VS Code extension (or any LSP client) spawns
//! `stealth-lsp` and receives diagnostics on `textDocument/didOpen` and
//! `textDocument/didSave` for Solidity files.

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::detectors::run_all_detectors;
use crate::suppression::filter_findings_by_inline_ignores;
use crate::types::{Finding, Severity};

pub struct StealthLsp {
    client: Client,
}

impl StealthLsp {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    fn scan_and_publish(&self, uri: Url, text: &str) {
        let diagnostics = scan_to_diagnostics(text);
        let client = self.client.clone();
        let uri = uri.clone();
        tokio::spawn(async move {
            client
                .publish_diagnostics(uri, diagnostics, None)
                .await;
        });
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for StealthLsp {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::FULL),
                        save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                            include_text: Some(true),
                        })),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "Stealth LSP server initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        if is_solidity_uri(&uri) {
            self.scan_and_publish(uri, &params.text_document.text);
        }
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        if is_solidity_uri(&uri) {
            if let Some(change) = params.content_changes.into_iter().last() {
                self.scan_and_publish(uri, &change.text);
            }
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;
        if is_solidity_uri(&uri) {
            if let Some(text) = params.text {
                self.scan_and_publish(uri, &text);
            }
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.client
            .publish_diagnostics(params.text_document.uri, vec![], None)
            .await;
    }
}

fn is_solidity_uri(uri: &Url) -> bool {
    uri.path().ends_with(".sol")
}

/// Run all detectors on `source` and convert findings to LSP diagnostics.
fn scan_to_diagnostics(source: &str) -> Vec<Diagnostic> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_solidity::LANGUAGE.into())
        .is_err()
    {
        return vec![];
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let mut findings: Vec<Finding> = Vec::new();
    run_all_detectors(&tree, source, &mut findings);
    let findings = filter_findings_by_inline_ignores(findings, source);

    findings.iter().map(|f| finding_to_diagnostic(f, source)).collect()
}

fn finding_to_diagnostic(finding: &Finding, source: &str) -> Diagnostic {
    let line = if finding.line > 0 {
        finding.line - 1
    } else {
        0
    };

    let line_len = source
        .lines()
        .nth(line as usize)
        .map(|l| l.len() as u32)
        .unwrap_or(0);

    let range = Range {
        start: Position {
            line: line as u32,
            character: 0,
        },
        end: Position {
            line: line as u32,
            character: line_len,
        },
    };

    let severity = match finding.severity {
        Severity::Critical | Severity::High => DiagnosticSeverity::ERROR,
        Severity::Medium => DiagnosticSeverity::WARNING,
        Severity::Low => DiagnosticSeverity::INFORMATION,
    };

    let message = if finding.suggestion.is_empty() {
        finding.message.clone()
    } else {
        format!("{}\nFix: {}", finding.message, finding.suggestion)
    };

    Diagnostic {
        range,
        severity: Some(severity),
        code: Some(NumberOrString::String(finding.vulnerability_type.clone())),
        source: Some("stealth".to_string()),
        message,
        ..Default::default()
    }
}

/// Start the LSP server on stdin/stdout.
pub async fn run_server() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(StealthLsp::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
