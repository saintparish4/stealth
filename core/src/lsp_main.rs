//! Entry point for the Stealth LSP server binary.
//!
//! Built with: cargo build --features lsp --no-default-features
//! The VS Code extension spawns this binary and communicates over stdio.

#[tokio::main]
async fn main() {
    stealth_scanner::lsp::run_server().await;
}
