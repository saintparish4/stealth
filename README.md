# Stealth - Smart Contract Security Scanner

A Solidity security scanner that detects common vulnerabilities through static analysis.

## What It Does

Stealth parses Solidity contracts and detects three categories of vulnerabilities:

1. **Reentrancy** - External calls followed by state changes
2. **Unchecked External Calls** - Missing return value checks on `.call()`
3. **tx.origin Authentication** - Using `tx.origin` for access control

## Installation

```bash
# Clone the repository
git clone <your-repo>
cd stealth

# Build from source
make build-release

# The binary will be at core/target/release/core
```

## Usage

```bash
# Scan the contracts directory (default)
make scan

# Scan a specific file
make scan FILE=core/contracts/multiple-vulnerabilities.sol

# Scan a specific directory
make scan FILE=core/contracts

# Scan with debug build (faster compilation)
make scan-debug

# View help
cd core && cargo run --release -- --help

# Check version
cd core && cargo run --release -- --version
```

## Example Output

```bash
$ make scan

Stealth Security Scan Results
Scanning directory: contracts

Found 7 file(s) to scan

Stealth Security Scan Results
Scanning: contracts/multiple-vulnerabilities.sol

Warning: 4 vulnerabilities found:

[HIGH] Reentrancy at line 17
 -> External call at line 17, state change at line 20
 Fix: Move state changes before external call, or add nonReentrant modifier

[MEDIUM] Unchecked Call at line 27
 -> External call return value is not checked
 Fix: Check the return value: (bool success, ) = addr.call(...); require(sucess, "Call failed");

[HIGH] tx.origin Authentication at line 32
 -> Using tx.origin for authorization is unsafe
 Fix: Use msg.sender insteaf of tx.origin for authentication checks

==================================================

Summary: Scanned 7 file(s), found 8 total vulnerability/vulnerabilities
```

## Test Contracts

The `core/contracts/` directory contains examples for each vulnerability type:

### Reentrancy
- `reentrancy-vulnerable.sol` - State change after external call ❌
- `reentrancy-safe.sol` - State change before external call ✅

### Unchecked Calls
- `unchecked-call-vulnerable.sol` - No return value check ❌
- `unchecked-call-safe.sol` - Proper return value check ✅

### tx.origin
- `tx-origin-vulnerable.sol` - Uses tx.origin for auth ❌
- `tx-origin-safe.sol` - Uses msg.sender for auth ✅

### Combined
- `multiple-vulnerabilities.sol` - All three vulnerability types

## Architecture

### Tech Stack
- **Rust** - Core implementation language
- **tree-sitter** - AST parsing
- **tree-sitter-solidity** - Solidity grammar
- **clap** - CLI argument parsing
- **colored** - Terminal output formatting

### Detection Approach

Stealth uses pattern matching on the Abstract Syntax Tree (AST):

**Reentrancy Detection:**
1. Find all function definitions
2. Collect statements in order
3. Flag external calls followed by state changes

**Unchecked Call Detection:**
1. Find expression statements containing `.call()`
2. Check if return value is captured
3. Flag calls without `(bool success, ) = ...` pattern

**tx.origin Detection:**
1. Find comparison expressions
2. Flag usage of `tx.origin` in equality checks
3. Suggest `msg.sender` alternative

### Severity Levels

- **CRITICAL** - Reserved for future use
- **HIGH** - Reentrancy, tx.origin auth
- **MEDIUM** - Unchecked external calls
- **LOW** - Reserved for future use

## Development Status

- ✅ Proper CLI with clap
- ✅ Three detector types
- ✅ Structured Finding system
- ✅ Colored terminal output
- ✅ Error handling
- ✅ Test contracts for all detectors
- ✅ Directory scanning support
- ✅ Makefile integration for easy usage

## Known Limitations

- Solidity 0.8.x focus (older versions may have different patterns)
- Pattern matching only (no dataflow analysis)
- No cross-function analysis for reentrancy

## Roadmap

- JSON output format for tooling integration
- Additional detectors based on real-world usage
- Improved pattern matching to reduce false positives
- Better handling of duplicate findings

## The Vulnerabilities Explained

### 1. Reentrancy

Occurs when a contract makes an external call before updating its state. An attacker can exploit this by recursively calling back into the vulnerable function.

**Vulnerable:**
```solidity
(bool success, ) = msg.sender.call{value: amount}("");
balances[msg.sender] -= amount;  // Attacker can re-enter before this
```

**Safe:**
```solidity
balances[msg.sender] -= amount;  // Update state first
(bool success, ) = msg.sender.call{value: amount}("");
```

### 2. Unchecked External Calls

The `.call()` function returns a boolean indicating success/failure. Ignoring this return value can lead to silent failures.

**Vulnerable:**
```solidity
recipient.call{value: amount}("");  // No return check
```

**Safe:**
```solidity
(bool success, ) = recipient.call{value: amount}("");
require(success, "Transfer failed");
```

### 3. tx.origin Authentication

`tx.origin` refers to the original external account that started the transaction. This can be exploited through phishing attacks where a malicious contract tricks a user into calling it.

**Vulnerable:**
```solidity
require(tx.origin == owner);  // Can be bypassed via intermediary contract
```

**Safe:**
```solidity
require(msg.sender == owner);  // Direct caller check
```

## Contributing
Feedback and suggestions welcome!
