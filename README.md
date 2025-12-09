# Stealth - Smart Contract Security Scanner

A Solidity security scanner that detects common vulnerabilities through static analysis.

## What It Does

Stealth parses Solidity contracts and detects seven categories of vulnerabilities:

1. **Reentrancy** [HIGH] - External calls followed by state changes

2. **Unchecked External Calls** [MEDIUM] - Missing return value checks on `.call()`

3. **tx.origin Authentication** [HIGH] - Using `tx.origin` for access control

4. **Missing Access Control** [HIGH] - Sensitive functions without auth checks

5. **Dangerous Delegatecall** [CRITICAL] - User-controlled delegatecall targets

6. **Timestamp Dependence** [LOW] - Relying on `block.timestamp` for critical logic

7. **Unsafe Randomness** [MEDIUM] - Using block properties for randomness

Each finding includes a **confidence level** (High/Medium/Low) to help prioritize fixes.

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

Vanguard provides exit codes for CI/CD pipelines:

- `0`: No vulnerabilities found
- `1`: Non-critical vulnerabilities found  
- `2`: Critical vulnerabilities found

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

## License

MIT
