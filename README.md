# Stealth - Smart Contract Security Scanner

**Version 0.4.0**

A Solidity security scanner that detects common vulnerabilities through static analysis with intelligent pattern recognition.

---

## Why Stealth?

I built Stealth to address the false positive problem that plagues other security scanners. Traditional tools flag legitimate DeFi patterns — user withdrawals, staking, claims — as vulnerabilities, creating noise that buries real issues. Stealth understands modern smart contract patterns and delivers accurate, actionable findings.

---

## Features

### 13 Vulnerability Detectors

| Detector | `detector_id` | Severity | OWASP SC Top 10 |
|----------|---------------|----------|-----------------|
| **Reentrancy** | `reentrancy` | HIGH | SC02 - Reentrancy Attacks |
| **Unchecked External Calls** | `unchecked-call` | MEDIUM | SC04 - Lack of Input Validation |
| **tx.origin Authentication** | `tx-origin` | HIGH | SC01 - Access Control Vulnerabilities |
| **Missing Access Control** | `access-control` | HIGH | SC01 - Access Control Vulnerabilities |
| **Dangerous Delegatecall** | `dangerous-delegatecall` | CRITICAL | SC01 - Access Control Vulnerabilities |
| **Timestamp Dependence** | `timestamp-dependence` | MEDIUM-HIGH | SC06 - Unsafe Randomness and Predictability |
| **Unsafe Randomness** | `unsafe-randomness` | HIGH | SC06 - Unsafe Randomness and Predictability |
| **Integer Overflow/Underflow** | `integer-overflow` | HIGH | SC03 - Integer Overflow and Underflow |
| **Flash Loan Vulnerability** | `flash-loan` | HIGH | SC07 - Flash Loan Attacks |
| **Storage Collision (Proxy)** | `storage-collision` | CRITICAL-HIGH | SC08 - Insecure Smart Contract Composition |
| **Front-Running Susceptibility** | `front-running` | MEDIUM-HIGH | SC09 - Denial of Service (DoS) Attacks |
| **DoS via Unbounded Loops** | `dos-loops` | HIGH | SC09 - Denial of Service (DoS) Attacks |
| **Unchecked ERC20 Return Values** | `unchecked-erc20` | HIGH | SC04 - Lack of Input Validation |

### Smart Analysis Capabilities

- **Self-Service Pattern Detection** — Recognizes DeFi patterns where users manage their own funds (`withdraw`, `claim`, `stake`) to avoid false positives on access control checks
- **Visibility-Aware Analysis** — Adjusts confidence based on function visibility (`private`/`internal` functions carry lower reentrancy risk)
- **Confidence Scoring** — Every finding includes High/Medium/Low confidence with contextual adjustments
- **Inline Suppression** — `// stealth-ignore: <rule>` comments silence specific findings at the source
- **Baseline Diffing** — Report only new findings against a known-good snapshot; ideal for CI ratchets
- **SARIF 2.1.0 Output** — Native SARIF for GitHub Code Scanning integration

---

## Project Structure

```
/core/              Rust scanner engine (binary + library)
  /src/
    /detectors/     13 vulnerability detectors (separate files)
    helpers.rs      Self-service + visibility utilities
    suppression.rs  Inline ignore + baseline filtering
    scan.rs         File and directory scanning
    output.rs       Terminal, JSON, and SARIF formatters
    types.rs        Finding, Severity, Confidence types
    lsp.rs          LSP server implementation (tower-lsp)
    lsp_main.rs     stealth-lsp binary entry point
    wasm.rs         WASM bindings (wasm-bindgen, future use)
    lib.rs          Library crate, feature-gated exports
    main.rs         stealth CLI binary entry point
  /contracts/       Example Solidity contracts for tests
/vscode-ext/        VS Code extension (LSP client)
  /src/
    extension.ts    Spawns stealth-lsp, registers diagnostics
/web/               Next.js web interface
  /app/             Pages, API routes, components
  /bin/             CI-built scanner binary (legacy name: vanguard)
/docs/              Technical documentation
  WASM_SIZE.md      WASM compilation investigation and LSP decision
/.github/
  /workflows/
    deploy.yml      Builds Rust binary and updates web/bin
```

---

## Tech Stack

| Technology | Purpose |
|------------|---------|
| **Rust** | Core scanner engine and LSP server |
| **tree-sitter** | Solidity AST parsing |
| **tower-lsp / tokio** | LSP server (VS Code extension backend) |
| **wasm-bindgen** | WASM bindings (future web migration) |
| **Next.js 16 / React 19** | Web interface |
| **Vercel** | Web app hosting |
| **GitHub Actions** | CI/CD |

---

## Installation

### From crates.io

```bash
cargo install stealth-scanner

# Use the installed binary
stealth scan ./contracts --recursive
```

### From Source

```bash
git clone https://github.com/saintparish4/stealth.git
cd stealth/core
cargo build --release

# Binary at: core/target/release/stealth
# Optionally install globally:
cargo install --path .
```

### Build the LSP Server (for VS Code extension)

```bash
cd core
cargo build --release --features lsp --no-default-features
# Binary at: core/target/release/stealth-lsp
```

---

## Usage

### Basic Scanning

```bash
# Scan a single file
stealth scan contracts/token.sol

# Scan a directory recursively
stealth scan contracts --recursive

# JSON output
stealth scan contracts --recursive --format json > results.json

# SARIF output (for GitHub Code Scanning)
stealth scan contracts --recursive --format sarif > results.sarif

# Using cargo run (development)
cd core
cargo run --release -- scan contracts --recursive
```

### Make Commands

```bash
make scan                                    # Scan core/contracts/
make scan FILE=core/contracts/token.sol      # Scan a specific file
make scan-debug                              # Debug build (faster recompile)
make build-release                           # Optimized release build
make verify                                  # Release build + verify.sh
```

### Command-Line Reference

```
stealth scan [PATH] [OPTIONS]

Arguments:
  <PATH>  Path to Solidity file or directory

Options:
  -f, --format <FORMAT>    Output format: terminal, json, sarif [default: terminal]
  -r, --recursive          Recursively scan directories
      --baseline <FILE>    Only report findings not in baseline JSON
  -h, --help               Print help
  -V, --version            Print version
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Low or medium severity findings only |
| `2` | High severity findings (may also have low/medium) |
| `3` | Critical severity findings (may also have any lower) |

### Suppression

Silence a specific finding inline:

```solidity
// stealth-ignore: reentrancy
(bool ok,) = msg.sender.call{value: amount}("");

// stealth-ignore: tx.origin
require(tx.origin == owner);
```

Target a specific line with `L<line>`: `// stealth-ignore: reentrancy L42`. Rule names are case-insensitive.

### Baseline Diffing

Fail CI only when *new* findings appear:

```bash
# 1. Capture a baseline from the current known state
stealth scan ./contracts --recursive --format json > baseline.json

# 2. In CI: only new findings are reported; exit 0 if nothing new
stealth scan ./contracts --recursive --baseline baseline.json
```

---

## Output Formats

**Terminal (default)** — Colored, human-readable output with a statistics summary.

**JSON** — Machine-readable for tool integration:

```bash
stealth scan contracts --recursive --format json
```

**SARIF 2.1.0** — For GitHub Code Scanning:

```bash
stealth scan contracts --recursive --format sarif > results.sarif
```

Upload to GitHub:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## VS Code Extension

The `vscode-ext/` directory contains a VS Code extension that provides inline Solidity diagnostics powered by an LSP server (`stealth-lsp`).

### How it works

The extension spawns `stealth-lsp` as a subprocess and communicates over stdio. On every file open and save, the LSP server scans the document and publishes diagnostics back to the editor.

### Setup

1. Build `stealth-lsp` and place it on your PATH (or configure `stealth.binaryPath`):

   ```bash
   cd core
   cargo build --release --features lsp --no-default-features
   # Copy core/target/release/stealth-lsp to somewhere on your PATH
   ```

2. Install the extension from the marketplace (or install the `.vsix` locally):

   ```bash
   cd vscode-ext
   npm install
   npm run package        # produces stealth-scanner-*.vsix
   code --install-extension stealth-scanner-*.vsix
   ```

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `stealth.binaryPath` | `""` | Path to `stealth-lsp`. Empty = use PATH. |
| `stealth.scanOnSave` | `true` | Auto-scan on file save. |
| `stealth.minimumSeverity` | `Low` | Minimum severity to report (`Critical`, `High`, `Medium`, `Low`). |

> **Note on WASM:** WASM compilation is currently blocked by tree-sitter's C dependencies. The extension uses the LSP subprocess approach instead. See [`docs/WASM_SIZE.md`](docs/WASM_SIZE.md) for details.

---

## CI/CD Integration

### GitHub Actions (inline)

```yaml
- name: Run Stealth Scan
  run: |
    cd core
    cargo build --release
    ./target/release/stealth scan ./contracts --recursive --format sarif > results.sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Block on critical findings:

```bash
stealth scan ./contracts --recursive
EXIT=$?
if [ $EXIT -ge 3 ]; then
  echo "Critical vulnerabilities found. Blocking deploy."
  exit 1
elif [ $EXIT -ge 2 ]; then
  echo "High severity findings detected."
  exit 1
fi
```

---

## Web Interface

The web app at `web/` provides a browser-based scanner with a Monaco code editor, real-time scan results, and syntax-highlighted output.

```bash
cd web
npm install
npm run dev
# Open http://localhost:3000
```

**Deployment:**

```bash
cd web
vercel --prod
```

For deployment notes, see the `web/` directory.

> **`web/bin/vanguard`** — The CI workflow builds the Rust scanner binary and commits it here under the legacy name `vanguard`. The CLI and docs use the name **Stealth**; both refer to the same binary. This pattern is being replaced by GitHub Releases + WASM in a future release.

---

## Testing

```bash
# All tests
cd core
cargo test

# Filter to detector or suppression tests
cargo test detector_
cargo test suppression_

# Full verification (release build + verify.sh)
make verify
```

---

## Building with Feature Flags

| Feature | What it enables |
|---------|----------------|
| `cli` (default) | `stealth` binary: terminal colors, file I/O, directory walking |
| `lsp` | `stealth-lsp` binary: LSP server via tower-lsp + tokio |
| `wasm` | WASM bindings via wasm-bindgen (currently blocked, see `docs/WASM_SIZE.md`) |

```bash
# CLI only (default)
cargo build --release

# LSP server only
cargo build --release --features lsp --no-default-features

# Both CLI and LSP
cargo build --release --features cli,lsp
```

---

## Limitations

Stealth performs static analysis only. It does not:

- Execute symbolic execution or formal verification
- Analyze complex business logic vulnerabilities
- Detect every possible attack vector
- Replace a professional security audit

For production deployments, use Stealth alongside comprehensive testing and a professional audit.

---

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for code style, commit message conventions, and the PR process.

---

## License

MIT
