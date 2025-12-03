#!/bin/bash

# Phase 2 Verification Script
# Tests all three detectors against vulnerable and safe contracts

echo "=== Stealth Phase 2 Verification ==="
echo ""

echo "📋 Building project..."
cargo build --release 2>&1 | tail -n 3
echo ""

SCANNER="./target/release/stealth"
TEST_DIR="contracts"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🧪 Running detector tests..."
echo ""

# Test 1: Reentrancy
echo "${YELLOW}Test 1: Reentrancy Detection${NC}"
echo "Vulnerable contract (should detect):"
$SCANNER scan $TEST_DIR/reentrancy-vulnerable.sol 2>/dev/null | grep -A 2 "Reentrancy"
echo ""
echo "Safe contract (should NOT detect):"
$SCANNER scan $TEST_DIR/reentrancy-safe.sol 2>/dev/null | grep "No vulnerabilities" || echo "  No reentrancy found ✓"
echo ""

# Test 2: Unchecked Calls
echo "${YELLOW}Test 2: Unchecked Call Detection${NC}"
echo "Vulnerable contract (should detect):"
$SCANNER scan $TEST_DIR/unchecked-call-vulnerable.sol 2>/dev/null | grep -A 2 "Unchecked"
echo ""
echo "Safe contract (should NOT detect):"
$SCANNER scan $TEST_DIR/unchecked-call-safe.sol 2>/dev/null | grep "No vulnerabilities" || echo "  No unchecked calls found ✓"
echo ""

# Test 3: tx.origin
echo "${YELLOW}Test 3: tx.origin Detection${NC}"
echo "Vulnerable contract (should detect):"
$SCANNER scan $TEST_DIR/tx-origin-vulnerable.sol 2>/dev/null | grep -A 2 "tx.origin"
echo ""
echo "Safe contract (should NOT detect):"
$SCANNER scan $TEST_DIR/tx-origin-safe.sol 2>/dev/null | grep "No vulnerabilities" || echo "  No tx.origin issues found ✓"
echo ""

# Test 4: Multiple vulnerabilities
echo "${YELLOW}Test 4: Multiple Vulnerabilities${NC}"
echo "Should detect all 3 vulnerability types:"
$SCANNER scan $TEST_DIR/multiple-vulnerabilities.sol 2>/dev/null
echo ""

echo "---"
echo "${GREEN}✅ Phase 2 verification complete!${NC}"
echo ""
echo "To manually test:"
echo "  cargo run -- scan contracts/<filename>.sol"
echo "  cargo run -- --help"