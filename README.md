# Stealth - Smart Contract Security Scanner

**Version 0.4.0**

A Solidity security scanner that detects common vulnerabilities through static analysis with intelligent pattern recognition.

---

## Why Stealth?

I built Stealth to address false positives that plague other security scanners. Traditional tools flag legitimate DeFi patterns (like user withdrawals and staking) as vulnerabilities, creating noise that obscures real issues. Stealth understands modern smart contract patterns and provides accurate, actionable security insights.

---

## Overview

Stealth parses Solidity contracts and identifies security issues before deployment. It provides confidence levels to help you prioritize fixes and supports both single file and recursive directory scanning, with output in terminal or JSON formats for CI/CD integration.

### What's New in v0.4.0

- **13 Comprehensive Detectors**: Expanded from 7 to 13 vulnerability detectors covering modern DeFi attack vectors
- **Self-Service Pattern Detection**: Automatically identifies user-operated functions (withdraw, claim, stake) to reduce false positives on access control checks
- **Visibility-Aware Analysis**: Adjusts reentrancy confidence based on function visibility (private/internal functions are lower risk)
- **Flash Loan Vulnerability Detection**: Identifies price manipulation and unvalidated callback patterns
- **Front-Running Detection**: Catches missing slippage protection, approval race conditions, and front-runnable auctions
- **DoS via Unbounded Loops**: Detects gas griefing patterns and external calls in loops
- **Enhanced Detectors**: Improved accuracy across all vulnerability categories
- **Context-Aware Heuristics**: Analysis that understands modern DeFi patterns

---

## Features

| Category | Severity | Description | Enhancements |
|----------|----------|-------------|--------------|
| **Reentrancy Detection** | HIGH | Identifies external calls followed by state changes | Visibility-aware confidence scoring |
| **Unchecked External Calls** | MEDIUM | Catches missing return value checks on `.call()` | High confidence pattern matching |
| **tx.origin Authentication** | HIGH | Flags insecure use of `tx.origin` for access control | Definitive anti-pattern detection |
| **Missing Access Control** | HIGH | Detects sensitive functions without auth checks | Self-service pattern recognition |
| **Dangerous Delegatecall** | CRITICAL | Warns about user-controlled delegatecall targets | Parameter analysis for user control |
| **Timestamp Dependence** | MEDIUM-HIGH | Flags dangerous timestamp patterns (modulo, equality) | View/pure function awareness |
| **Unsafe Randomness** | HIGH | Detects use of block properties for randomness | Pattern-based detection (keccak256, blockhash) |
| **Integer Overflow/Underflow** | HIGH | Detects unsafe arithmetic in Solidity <0.8 and unchecked blocks | Version-aware detection |
| **Flash Loan Vulnerability** | HIGH | Identifies price manipulation and unvalidated callbacks | Spot price vs TWAP detection |
| **Storage Collision (Proxy)** | CRITICAL-HIGH | Detects missing storage gaps and unprotected initializers | Upgradeable contract patterns |
| **Front-Running Susceptibility** | MEDIUM-HIGH | Catches missing slippage protection, approval race conditions | Swap/withdraw pattern analysis |
| **DoS via Unbounded Loops** | HIGH | Detects gas griefing and external calls in loops | Array iteration analysis |
| **Unchecked ERC20 Return Values** | HIGH | Flags missing SafeERC20 usage | Transfer/approve pattern detection |

**Smart Analysis Capabilities:**
- **Self-Service Pattern Detection** - Understands DeFi patterns where users manage their own funds (withdraw, claim, stake) to avoid false positives
- **Visibility-Aware Analysis** - Adjusts confidence based on function visibility (private/internal = lower risk)
- **Confidence Scoring** - Each finding includes High/Medium/Low confidence with intelligent adjustments
- **Recursive Scanning** - Analyze entire contract directories at once
- **Multiple Output Formats** - Terminal (colored) or JSON for tooling integration
- **CI/CD Ready** - Exit codes (0/1/2) for pipeline integration
- **Fast Analysis** - Built with Rust for maximum performance

---

## Tech Stack

| Technology | Purpose |
|------------|---------|
| **Rust** | Core scanner engine (performance & safety) |
| **Cargo** | Build system & package manager |
| **Solidity** | Target language for vulnerability detection |
| **Next.js** | Web interface for the scanner |
| **Vercel** | Hosting platform for web application |
| **GitHub Actions** | CI/CD workflow support |

---

## Installation

### Install from crates.io (Recommended)

```bash
# Install the latest version from crates.io
cargo install stealth-scanner

# After installation, use the 'stealth' command
stealth scan ./contracts --recursive
```

### Install from Source

```bash
# Clone the repository
git clone https://github.com/saintparish4/stealth.git
cd stealth

# Build from source
cd core
cargo build --release

# The binary will be at core/target/release/stealth

# Optional: Install globally from source
cargo install --path .

# After installation, you can use 'stealth' command directly
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

## Limitations

Stealth focuses on detecting common vulnerability patterns through static analysis. It does not:

- Perform symbolic execution or formal verification
- Analyze complex business logic vulnerabilities
- Detect all possible attack vectors (no tool can)
- Replace professional security audits

For production deployments, I recommend using Stealth alongside professional audits and comprehensive testing.

---

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.

---

## Web Interface

Stealth includes a modern web interface built with Next.js. The web application provides:

- Interactive code editor with syntax highlighting
- Real-time vulnerability scanning
- Beautiful results visualization
- Easy sharing of scan results

### Deployment

The web application is deployed on Vercel. For deployment instructions, see:
- `web/DEPLOYMENT.md` - Complete deployment guide
- `web/QUICK_START.md` - Quick reference for common tasks

### Local Development

```bash
cd web
npm install
npm run dev
# Open http://localhost:3000
```

### Production Deployment

```bash
cd web
vercel --prod
```

The web application automatically includes the Rust scanner binary, which is built and bundled during the CI/CD process.

---

## License

MIT
