# WASM Status & VS Code Extension Strategy

## Decision: LSP Subprocess (not WASM)

**Date:** 2026-02-19
**Status:** WASM deferred; LSP subprocess adopted for VS Code extension

## WASM Compilation Blocker

Building with `wasm-pack build --target web --features wasm --no-default-features` fails
because `tree-sitter-solidity` compiles C code via the `cc` crate. The
`wasm32-unknown-unknown` target lacks a C standard library, so clang cannot find
`<stdlib.h>`:

```
tree_sitter/parser.h:10:10: fatal error: 'stdlib.h' file not found
```

**Root cause:** `wasm32-unknown-unknown` has no libc. The `cc` crate invokes
`clang --target=wasm32-unknown-unknown` which has no sysroot with C headers.

**Possible fixes (for future reference):**

1. Install [wasi-sdk](https://github.com/WebAssembly/wasi-sdk) and set
   `CC_wasm32_unknown_unknown` to its clang with `--sysroot`.
2. Use `wasm32-unknown-emscripten` target (provides libc but loses wasm-bindgen
   compatibility).
3. Wait for tree-sitter to ship a pure-Rust Solidity grammar (eliminates C
   dependency entirely).

## Why LSP Subprocess

- Uses the **already-working native binary** -- zero new compilation targets.
- Standard pattern for VS Code language extensions (rust-analyzer, clangd, solc-ls).
- Full filesystem access -- can scan entire projects, not just open files.
- No binary size concerns (WASM bundles were projected 2-5 MB+).
- Can be upgraded to WASM later if the toolchain issue is resolved.

## Current Architecture

```
VS Code Extension (TypeScript)
  └─ spawns stealth-lsp binary over stdio
       └─ Stealth scanner engine (Rust)
            └─ 13 detectors, suppression, diagnostics
```

The extension is a thin LSP client (`vscode-languageclient`). All scanning logic
lives in the Rust `stealth-lsp` binary, built with `cargo build --features lsp
--no-default-features`.

## WASM Future Path

The `wasm` feature and `core/src/wasm.rs` remain in the codebase. Once the C
cross-compilation toolchain issue is resolved (via wasi-sdk or a pure-Rust
tree-sitter grammar), WASM can be used for:

- **Web app migration** -- replace the child-process binary with in-browser WASM
- **VS Code web extensions** -- run in vscode.dev without a native binary
- **Playground / embeds** -- scan Solidity in any browser context
