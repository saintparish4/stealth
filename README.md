# Stealth - Smart Contract Security Scanner

A Solidity security scanner that detects common vulnerabilities through static analysis.

---

## Overview

**Stealth** parses Solidity contracts and identifies security issues before deployment, providing confidence levels to help developers prioritize fixes. The tool supports both single file and recursive directory scanning, with output in terminal or JSON formats for easy CI/CD integration.

---

## Features

| Category | Severity | Description |
|----------|----------|-------------|
| **Reentrancy Detection** | HIGH | Identifies external calls followed by state changes |
| **Unchecked External Calls** | MEDIUM | Catches missing return value checks on `.call()` |
| **tx.origin Authentication** | HIGH | Flags insecure use of `tx.origin` for access control |
| **Missing Access Control** | HIGH | Detects sensitive functions without auth checks |
| **Dangerous Delegatecall** | CRITICAL | Warns about user-controlled delegatecall targets |
| **Timestamp Dependence** | LOW | Flags reliance on `block.timestamp` for critical logic |
| **Unsafe Randomness** | MEDIUM | Detects use of block properties for randomness |

**Additional Capabilities:**
- **Confidence Scoring** — Each finding includes High/Medium/Low confidence levels
- **Recursive Scanning** — Analyze entire contract directories at once
- **Multiple Output Formats** — Terminal (colored) or JSON for tooling
- **CI/CD Ready** — Exit codes (0/1/2) for pipeline integration
- **Fast Analysis** — Built for speed with release builds

---

## Tech Stack

| Technology | Purpose |
|------------|---------|
| **Rust** | Core scanner engine (performance & safety) |
| **Cargo** | Build system & package manager |
| **Solidity** | Target language for vulnerability detection |
| **GitHub Actions** | CI/CD workflow support |

---

## Installation

```bash
# Clone the repository
git clone <your-repo>
cd stealth

# Build from source
cd core
cargo build --release

# The binary will be at core/target/release/core

# Optional: Install globally as 'stealth'
cargo install --path .

# After installation, use 'stealth' command directly
stealth scan ./contracts --recursive
```

---

## Usage

### Basic Scanning

```bash
# Using cargo run (development)
cd core

# Scan a single file
cargo run --release -- scan contracts/reentrancy-vulnerable.sol

# Scan a directory recursively
cargo run --release -- scan contracts --recursive

# Get JSON output
cargo run --release -- scan contracts/reentrancy-vulnerable.sol --format json

# Scan directory with JSON output
cargo run --release -- scan contracts --recursive --format json > results.json

# Using installed binary (after cargo install)
stealth scan contracts/reentrancy-vulnerable.sol
stealth scan contracts --recursive
stealth scan contracts --recursive --format json > results.json

# Using Make (recommended)
make scan                                    # Scan contracts/ directory
make scan FILE=core/contracts/reentrancy-vulnerable.sol
make scan FILE=core/contracts
make scan-debug                              # Faster compilation for testing
```

### CI/CD Integration

Stealth provides exit codes for CI/CD pipelines:

| Exit Code | Meaning |
|-----------|---------|
| `0` | No vulnerabilities found |
| `1` | Non-critical vulnerabilities found |
| `2` | Critical vulnerabilities found |

```bash
# In your CI/CD script
cd core
cargo run --release -- scan contracts --recursive --format json

EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
  echo "Critical vulnerabilities found! Blocking deployment."
  exit 1
fi
```

### GitHub Actions

See `.github/workflows/stealth-security-scan.yml` for a complete example.

```yaml
- name: Run Stealth Scan
  run: |
    cd core
    cargo run --release -- scan ./contracts --recursive --format json
```

### Output Formats

**Terminal (default):**

```bash
cd core
cargo run --release -- scan contracts/comprehensive-vulnerabilities.sol
```

Clean, colored output with statistics summary.

**JSON:**

```bash
cd core
cargo run --release -- scan contracts/comprehensive-vulnerabilities.sol --format json
```

Machine-readable format for tool integration.

### Command-line Options

```bash
stealth scan [PATH] [OPTIONS]

Arguments:
  <PATH>  Path to Solidity file or directory

Options:
  -f, --format <FORMAT>      Output format: terminal or json [default: terminal]
  -r, --recursive           Recursively scan directories
  -h, --help                Print help
  -V, --version             Print version
```

---

## License

MIT
