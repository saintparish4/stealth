# Vanguard - Smart Contract Security Scanner

A Solidity security scanner that detects common vulnerabilities through static analysis.

## What It Does

Vanguard parses Solidity contracts and detects seven categories of vulnerabilities:

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
$ make scan FILE=core/contracts/comprehensive-vulnerabilities.sol

Vanguard Security Scan Results
Scanning: contracts/comprehensive-vulnerabilities.sol

⚠ 19 vulnerabilities found:

[HIGH] Reentrancy at line 19 (Confidence: High)
  → External call at line 19, state change at line 22
  Fix: Move state changes before external call, or add nonReentrant modifier

[MEDIUM] Unchecked Call at line 27 (Confidence: High)
  → External call return value is not checked
  Fix: Check the return value: (bool success, ) = addr.call(...); require(success, "Call failed");

[HIGH] tx.origin Authentication at line 32 (Confidence: High)
  → Using tx.origin for authorization is unsafe
  Fix: Use msg.sender instead of tx.origin for authentication checks

[HIGH] Missing Access Control at line 37 (Confidence: Medium)
  → Sensitive function may lack access control
  Fix: Add require(msg.sender == owner) or use an access control modifier

[CRITICAL] Dangerous Delegatecall at line 43 (Confidence: Medium)
  → delegatecall to potentially user-controlled address
  Fix: Ensure delegatecall target is hardcoded or strictly validated. Consider using library pattern.

[LOW] Timestamp Dependence at line 48 (Confidence: Medium)
  → Using block.timestamp for critical logic can be manipulated by miners
  Fix: Avoid using block.timestamp for critical decisions. If needed, allow ~15 minute tolerance.

[MEDIUM] Unsafe Randomness at line 53 (Confidence: High)
  → Using block properties for randomness is predictable
  Fix: Use Chainlink VRF or commit-reveal scheme for true randomness
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

### Access Control
- `access-control-safe.sol` - Proper access control modifiers ✅

### Delegatecall
- `delegatecall-vulnerable.sol` - User-controlled delegatecall ❌
- `delegatecall-safe.sol` - Hardcoded library address ✅

### Timestamp Dependence
- `timestamp-vulnerable.sol` - Exact timestamp checks ❌
- `timestamp-safe.sol` - Reasonable time tolerance ✅

### Unsafe Randomness
- `randomness-vulnerable.sol` - Block properties for RNG ❌
- `randomness-safe.sol` - Commit-reveal scheme ✅

### Combined
- `multiple-vulnerabilities.sol` - First 3 vulnerability types
- `comprehensive-vulnerabilities.sol` - All 7 vulnerability types

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
4. High confidence for balance mapping changes, medium for others

**Unchecked Call Detection:**
1. Find expression statements containing `.call()`
2. Check if return value is captured
3. Flag calls without `(bool success, ) = ...` pattern

**tx.origin Detection:**
1. Find comparison expressions
2. Flag usage of `tx.origin` in equality checks
3. Suggest `msg.sender` alternative

**Access Control Detection:**
1. Find sensitive functions (withdraw, destroy, selfdestruct, etc.)
2. Check for require statements with msg.sender or modifiers
3. Flag functions lacking protection

**Delegatecall Detection:**
1. Find delegatecall usage in code
2. Flag as potentially dangerous (needs manual review)
3. Recommend hardcoded addresses

**Timestamp Detection:**
1. Find block.timestamp in conditionals
2. Flag exact timing dependencies
3. Suggest reasonable tolerance ranges

**Randomness Detection:**
1. Find block properties (blockhash, block.number)
2. Check for modulo operations (% operator)
3. Recommend Chainlink VRF or commit-reveal

### Confidence Levels

Each finding includes a confidence rating:
- **High**: Very likely a real vulnerability
- **Medium**: Potentially vulnerable, needs review
- **Low**: May be intentional, check context

This helps prioritize which findings to fix first.

### Severity Levels
- **CRITICAL** - Dangerous delegatecall (complete contract takeover possible)
- **HIGH** - Reentrancy, tx.origin auth, missing access control
- **MEDIUM** - Unchecked external calls, unsafe randomness
- **LOW** - Timestamp dependence


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

### 4. Missing Access Control

Sensitive functions (withdraw, destroy, selfdestruct) without proper authorization checks can be called by anyone.

**Vulnerable:**
```solidity
function withdraw() public {  // Anyone can call this!
    payable(msg.sender).transfer(address(this).balance);
}
```

**Safe:**
```solidity
function withdraw() public {
    require(msg.sender == owner, "Not authorized");
    payable(msg.sender).transfer(address(this).balance);
}
```

### 5. Dangerous Delegatecall

`delegatecall` executes code in the context of the calling contract. If the target address is user-controlled, an attacker can modify the contract's storage.

**Vulnerable:**
```solidity
function execute(address target, bytes memory data) public {
    target.delegatecall(data);  // Attacker controls target!
}
```

**Safe:**
```solidity
address immutable trustedLibrary = 0x...;  // Hardcoded
function execute(bytes memory data) public {
    trustedLibrary.delegatecall(data);  // Only trusted code
}
```

### 6. Timestamp Dependence

Miners can manipulate `block.timestamp` within a ~15 second window. Using exact timestamps for critical logic is dangerous.

**Vulnerable:**
```solidity
require(block.timestamp % 15 == 0);  // Exact timing
```

**Safe:**
```solidity
require(block.timestamp >= deadline);  // Reasonable tolerance
```

### 7. Unsafe Randomness

Block properties (blockhash, block.number, block.difficulty) are predictable and can be manipulated by miners.

**Vulnerable:**
```solidity
uint random = uint(blockhash(block.number - 1)) % 100;  // Predictable!
```

**Safe:**
```solidity
// Use Chainlink VRF for true randomness, or:
// Implement commit-reveal scheme
bytes32 public commitment;
function commit(bytes32 hash) public { commitment = hash; }
function reveal(uint nonce) public { /* verify and use */ }
```
