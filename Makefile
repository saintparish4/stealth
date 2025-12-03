.PHONY: help build build-release run scan scan-debug verify clean test

# Variables
CARGO = cargo
CORE_DIR = core
SCANNER = $(CORE_DIR)/target/release/core
SCANNER_DEBUG = $(CORE_DIR)/target/debug/core
CONTRACTS_DIR = $(CORE_DIR)/contracts

# Default target
help:
	@echo "Stealth - Solidity Security Scanner"
	@echo ""
	@echo "Available targets:"
	@echo "  make build          - Build in debug mode"
	@echo "  make build-release  - Build in release mode (optimized)"
	@echo "  make run            - Run scanner with default args"
	@echo "  make scan [FILE=...]  - Scan a Solidity file or directory (release build)"
	@echo "                         Defaults to contracts/ if FILE not specified"
	@echo "  make scan-debug [FILE=...] - Scan with debug build (faster compilation)"
	@echo "                               Defaults to contracts/ if FILE not specified"
	@echo "  make verify         - Run verification tests"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make test           - Alias for verify"
	@echo ""
	@echo "Examples:"
	@echo "  make build-release"
	@echo "  make scan                    # Scans contracts/ directory"
	@echo "  make scan FILE=contracts/reentrancy-vulnerable.sol"
	@echo "  make scan FILE=contracts"
	@echo "  make scan-debug              # Scans contracts/ directory (debug build)"
	@echo "  make scan-debug FILE=contracts/tx-origin-vulnerable.sol"
	@echo "  make verify"

# Build targets
build:
	@echo "Building in debug mode..."
	cd $(CORE_DIR) && $(CARGO) build

build-release:
	@echo "Building in release mode..."
	cd $(CORE_DIR) && $(CARGO) build --release

# Run targets
run: build-release
	@echo "Running scanner..."
	cd $(CORE_DIR) && $(CARGO) run --release --

FILE ?= contracts

scan: build-release
	@echo "Scanning $(FILE)..."
	cd $(CORE_DIR) && $(CARGO) run --release -- scan $(FILE)

scan-debug: build
	@echo "Scanning $(FILE)..."
	cd $(CORE_DIR) && $(CARGO) run -- scan $(FILE)

# Test/Verify targets
verify: build-release
	@echo "Running verification tests..."
	cd $(CORE_DIR) && bash verify.sh

test: verify

# Clean target
clean:
	@echo "Cleaning build artifacts..."
	cd $(CORE_DIR) && $(CARGO) clean

