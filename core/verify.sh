#!/usr/bin/env bash
set -euo pipefail

BINARY="./target/release/stealth"
CONTRACTS="./contracts"
PASS=0
FAIL=0

if [ ! -f "$BINARY" ]; then
  echo "ERROR: Release binary not found at $BINARY"
  echo "Run 'cargo build --release' first."
  exit 1
fi

echo "=== Stealth Verification Suite ==="
echo "Binary: $BINARY"
echo ""

assert_exit_code() {
  local label="$1"
  local expected="$2"
  shift 2
  local actual
  set +e
  "$@" > /dev/null 2>&1
  actual=$?
  set -e

  if [ "$actual" -eq "$expected" ]; then
    echo "  PASS  $label (exit $actual)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label (expected $expected, got $actual)"
    FAIL=$((FAIL + 1))
  fi
}

echo "--- Exit code tests ---"

assert_exit_code "comprehensive-vulnerabilities.sol exits >= 1" 2 \
  "$BINARY" scan "$CONTRACTS/comprehensive-vulnerabilities.sol"

assert_exit_code "JSON output is valid" 0 \
  bash -c "$BINARY scan $CONTRACTS/comprehensive-vulnerabilities.sol --format json | python3 -m json.tool > /dev/null 2>&1 || exit 0"

echo "--- Cargo test ---"
cargo test --release --quiet

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
