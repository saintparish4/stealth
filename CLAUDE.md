# Stealth Development Guide

## Project Structure

```
/core/              - Rust scanner engine (binary + library)
  /src/             - Scanner logic, detectors, output, suppression
  /contracts/        - Example Solidity contracts for tests and validation
/web/               - Next.js App Router application (scanner UI)
  /app/             - Pages and UI components
  /bin/             - Bundled scanner binary (e.g. vanguard) for web
/docs/              - Documentation and guides
.github/            - Workflows, issue/PR templates, stale bot
```

## Technology Stack

- **Rust:** Core scanner (Cargo, standard library)
- **Solidity:** Target language for vulnerability detection (parsed, not executed)
- **Next.js:** Web UI (App Router); TypeScript, React
- **Build:** Make (optional), Cargo, npm
- **Testing:** `cargo test`, `verify.sh` (core); `npm run lint` / `npm run build` (web)
- **CI:** GitHub Actions (build, test, deploy)

## Local Development

See `CONTRIBUTING.md` for full setup. Quick start:

```bash
# Core scanner
cd core && cargo build --release

# Web app
cd web && npm install && npm run dev
```

- **Web URL:** http://localhost:3000
- **Scan from CLI:** `make scan` or `cd core && cargo run --release -- scan ./contracts --recursive`

## Testing

Run from repo root or `core/`:

```bash
# Core: all tests
cd core && cargo test

# Core: detector or suppression tests only
cd core && cargo test detector_
cd core && cargo test suppression_

# Full verification (release build + verify.sh)
make verify

# Web: lint and build
cd web && npm run lint && npm run build
```

**Tip:** Use `make scan-debug` for faster iteration (debug build, no `--release`).

## Code Quality

No Docker required. Run on host:

```bash
# Rust format
make fmt
# or: cd core && cargo fmt

# Core verification (build + verify script)
make verify

# Optional: Clippy (if configured)
cd core && cargo clippy

# Web
cd web && npm run lint
cd web && npm run build
```

## Build Commands

```bash
make build          # Debug build
make build-release  # Release build (optimized)
make scan           # Scan core/contracts (release)
make scan FILE=path/to/file.sol
make scan-debug     # Scan with debug build (faster compile)
make verify         # Run verification tests
make clean          # Clean build artifacts
```

## Coding Standards

- **Rust:** snake_case (functions/variables), PascalCase (types). Run `cargo fmt`. Document public APIs with doc comments.
- **TypeScript/Next.js:** TypeScript throughout; App Router conventions; `'use client'` only where needed. Run `npm run lint`.
- **Line endings:** LF (Unix)
- **New detector code:** Add tests under `core/contracts`; document detector logic and confidence in code or `/docs`.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

**Types:** feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert

**Scopes (examples):** detector, scanner, core, web, contracts, docs, deps

**Examples:**

- `feat(detector): add flash loan callback validation`
- `fix(scanner): resolve false positive in reentrancy detection`
- `docs(readme): update installation instructions`
- `chore(deps): bump Next.js to 16.1.0`

**Breaking changes:** Add `!` after type/scope or use `BREAKING CHANGE:` in footer. See `CONTRIBUTING.md`.

## Detector Guidelines (Core)

- Add or update test contracts in `/core/contracts` for new or changed detectors.
- Cover both vulnerable and safe patterns; document confidence and edge cases.
- Reduce false positives; consider self-service patterns (withdraw, claim, stake) and visibility (public vs internal/private).
- Inline suppression: `// stealth-ignore: <rule>` (and optional `L<line>`). Document in README.

## Common Gotchas

- **Web binary:** The web app bundles the scanner under the legacy name `vanguard` (e.g. `web/bin/vanguard`); CLI and docs use **Stealth**. Same engine.
- **Exit codes:** 0 = no findings, 1 = non-critical, 2 = critical. CI should treat 2 as failure when appropriate.
- **Baseline:** `--baseline file.json` reports only findings not in the baseline; use for “fail on new only” in CI.
- Pre-commit hooks (e.g. commit-msg for Conventional Commits) are optional; see `CONTRIBUTING.md`.

## Key Documentation

- `README.md` - Overview, installation, usage, detectors
- `CONTRIBUTING.md` - Contributing guidelines, PR process, code style
- `.github/SECURITY.md` - Security policy and reporting
- `web/DEPLOYMENT.md`, `web/QUICK_START.md` - Web app deployment and quick start
