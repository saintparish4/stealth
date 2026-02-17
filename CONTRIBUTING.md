# Contributing to Stealth

Thank you for your contribution. Stealth (and smart contract security tooling) continues to get better because of people like you!

The maintainers want to get your pull request in as seamlessly as possible, so please ensure your code is consistent with the development guidelines below.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Project Structure

| Path | Purpose |
|------|---------|
| `/core/contracts` | Example Solidity contracts for testing and validation |
| `/core/src` | Rust source code for the scanner engine |
| `/web/app` | Next.js App Router application with UI components |
| `/docs` | Documentation and guides |

## Commit Messages

Stealth uses [Conventional Commits](https://www.conventionalcommits.org/) for all commits merged to `main` and release branches. Your PR title must follow this format:

```
<type>(<scope>): <description>
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Code style (formatting, whitespace) |
| `refactor` | Code refactoring (no feature/fix) |
| `perf` | Performance improvement |
| `test` | Adding/updating tests |
| `build` | Build system or dependencies |
| `ci` | CI configuration |
| `chore` | Maintenance tasks |
| `revert` | Revert a previous commit |

### Examples

- `feat(detector): add flash loan vulnerability detection`
- `fix(scanner): resolve false positive in reentrancy detection`
- `docs(readme): update installation instructions`
- `chore(deps): bump Next.js to 16.1.0`

### Scopes

Scopes are optional but encouraged. Use them to indicate the area affected (e.g. `scanner`, `detector`, `web`, `core`, `contracts`, `docs`, `deps`).

### Breaking Changes

For breaking changes, add `!` after the type/scope or include a `BREAKING CHANGE:` footer:

```
feat(api)!: change scan output JSON structure

BREAKING CHANGE: The JSON output now uses a different schema for findings.
```

### Local Validation

If you use [pre-commit](https://pre-commit.com/), you can install hooks to validate commit messages locally:

```sh
pre-commit install --hook-type commit-msg   # Validates commit message format
pre-commit install                          # Enables all configured hooks
```

## Code Quality (no Docker required)

Run these checks on your host before opening a PR:

```sh
# Format Rust code
make fmt
# or: cd core && cargo fmt

# Run core verification tests (builds release, runs verify.sh)
make verify

# Individual checks
cd core && cargo test          # Unit tests
cd core && cargo clippy        # Lints (if configured)

# Web application
cd web && npm run lint         # ESLint
cd web && npm run build        # Ensure build succeeds
```

These are the same kinds of checks CI will run.

## Getting Started (local development)

1. **Fork and clone**
   - [Fork the repository](https://github.com/your-username/stealth/fork) and clone your fork locally.
   - (Optional) Add an `upstream` remote to keep your fork in sync; see [this guide](https://oneemptymind.wordpress.com/2018/07/11/keeping-a-fork-up-to-date/) for one approach.

2. **Install Rust** (required for the core scanner)
   - [Rust installation guide](https://www.rust-lang.org/tools/install)
   - Verify: `rustc --version` and `cargo --version`

3. **Install Node.js** (LTS recommended) for the web interface
   - [Node.js downloads](https://nodejs.org/en/download)

4. **Build and run**
   - Core scanner:
     ```sh
     cd core && cargo build --release
     ```
   - Web app:
     ```sh
     cd web && npm install && npm run dev
     ```
   - Open http://localhost:3000 in your browser.

5. **Make changes**
   - Edit files on your local machine. Refresh the browser for web changes.
   - For Rust changes, rebuild with `cargo build` (or `make build-release` from repo root).

6. **Verify before submitting**
   - Run `make verify` from the repo root.
   - Run `make fmt` and `cd web && npm run lint`.

7. **Submit a PR**
   - Open a [pull request](https://github.com/your-username/stealth/compare) from your fork into the default branch (e.g. `main`).

## Development Guidelines

- **Keep changes focused.** Large PRs are harder to review. Consider opening an issue first to discuss bigger changes.
- **Type safety.** Use TypeScript fully in the web app and leverage Rust’s type system in the core scanner.
- **Clear code.** Prefer self-explanatory names; add comments only where logic is non-obvious (e.g. detector heuristics).
- **Consistent API.** Keep the scanner interface and web app API consistent and predictable.
- **Follow existing style.** Match Rust and TypeScript conventions already used in the repo.
- **Stability.** Avoid changes that break scanning workflows or existing scan result formats without good reason.

## Testing

All contributions should include appropriate tests:

- **Rust:** Add or update unit tests; run with `cargo test` and `make verify`.
- **Detectors:** Add or update test contracts under `/core/contracts` and ensure both vulnerable and safe patterns are covered.
- **Web:** Run `npm run lint` and `npm run build`; manually test UI changes.
- Update tests when your changes affect existing behavior.

## Pull Request Process

1. Create a branch with a clear purpose (e.g. `feat/detector-flash-loan`, `fix/scanner-reentrancy`).
2. Make changes following the guidelines above; run `make verify`, `make fmt`, and web lint/build.
3. Commit with Conventional Commits; the PR title should follow `<type>(<scope>): <description>`.
4. Open a PR (draft is fine for early feedback). Reference related issues (e.g. “Closes #123”).
5. Keep the PR focused on one feature or fix; respond to review feedback and push updates to the same branch.

## After You Submit

- **First-time contributors:** A maintainer may need to approve your PR before CI runs (e.g. GitHub security for first-time contributors).
- **Automated checks** typically include: commit message format, Rust format/tests, web lint/build. See the repo’s CI configuration for details.
- **Review:** A maintainer will review your PR. Address feedback and push to the same branch; the PR will update automatically.

We look forward to your contribution.

---

## Code Style

**Rust (core scanner)**

- Follow Rust naming (snake_case for functions/variables, PascalCase for types).
- Run `cargo fmt` before committing.
- Use the type system and pattern matching; document public APIs with doc comments.

**TypeScript/Next.js (web)**

- Use TypeScript types and interfaces; follow Next.js conventions (Server Components by default, `'use client'` where needed).
- Run `npm run lint` before committing.
- Prefer functional components and hooks; follow React and App Router best practices.

## Component-Specific Guidelines

### Core scanner (`/core`)

- When adding detectors, add or update test contracts in `/core/contracts` and document detector logic and confidence scoring.
- Handle edge cases and aim to reduce false positives.
- Keep detector behavior and confidence levels documented (e.g. in `/docs`).

### Web application (`/web`)

- Follow Next.js App Router conventions; keep UI accessible and responsive.
- Test scanner integration with different contract sizes and output formats.

### Documentation (`/docs`)

- Keep docs in sync with code; use clear language and code examples where helpful.
- Document detector behavior and confidence levels where relevant.

## Security Issues

If you discover a security vulnerability, please report it responsibly. See our [Security Policy](SECURITY.md). Do not disclose issues publicly before they are addressed.
