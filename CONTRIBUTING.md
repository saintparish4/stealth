# Contributing to Stealth 

Thank you for your interest in contributing to Stealth. This guide will help you get started with the contribution process.

## Code of Conduct 

This project and everyone participating in it is governed by our [Code of Conduct](/CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Project Structure 

The Stealth repo is organized as follows:

- `/core/contracts` - Example Solidity contracts for testing and validation
- `/core/src` - Rust source code for the scanner engine
- `/web/app` - Next.js App Router application with UI components
- `/docs` - Documentation and guides

## Development Guidelines 

When contributing to Stealth:

- Keep changes focused. Large PRs are harder to review and unlikely to be accepted. We recommend opening an issue and discussing it with us first.
- Ensure all code is type-safe. Use TypeScript features fully in the web application and leverage Rust's type system in the core scanner.
- Write clear, self-explanatory code. Use comments only when truly necessary, especially for complex vulnerability detection logic.
- Maintain a consistent and predictable API across the scanner interface and web application.
- Follow the existing code style and conventions in both Rust and TypeScript codebases.
- We aim for stability, so avoid changes that would require users to update their scanning workflows or break existing scan result formats.

## Getting Started 

1. Fork the repository to your GitHub account
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/stealth.git
   cd stealth
   ```
3. Install Rust (required for the core scanner):

   > **Note**: This project requires Rust to build the core scanner. See the [Rust installation guide](https://www.rust-lang.org/tools/install) for installation instructions.

   Once installed, verify your installation:
   ```bash
   rustc --version
   cargo --version
   ```

4. Install Node.js (LTS version recommended) for the web interface:

   > **Note**: This project uses Node.js for the Next.js web application. See [Node.js installation](https://nodejs.org/en/download) for supported methods.

5. Install project dependencies:

   For the core scanner (Rust):
   ```bash
   cd core
   cargo build
   ```

   For the web application:
   ```bash
   cd web
   npm install
   ```

6. Build the project:

   Build the core scanner:
   ```bash
   cd core
   cargo build --release
   ```

   Build the web application:
   ```bash
   cd web
   npm run build
   ```

7. Run the web application locally:
   ```bash
   cd web
   npm run dev
   ```
   Open http://localhost:3000 in your browser.

## Code Formatting

We use standard formatting tools for both codebases. Before committing, please ensure your code is properly formatted:

**For Rust code (core scanner):**
```bash
cd core
cargo fmt
```

**For TypeScript/JavaScript code (web application):**
```bash
cd web
npm run lint
```

## Development Workflow

1. Create a new branch for your changes:
   ```bash
   git checkout -b type/description
   # Example: git checkout -b feat/flash-loan-detector
   ```
   
   Branch type prefixes:
   - `feat/` - New features (e.g., new vulnerability detectors)
   - `fix/` - Bug fixes
   - `docs/` - Documentation changes
   - `refactor/` - Code refactoring
   - `test/` - Test-related changes
   - `chore/` - Build process or tooling changes

2. Make your changes following the code style guidelines
3. Add tests for your changes
4. Run the test suite:
   ```bash
   # Test the core scanner
   cd core
   cargo test
   
   # Or use the Makefile
   make verify
   
   # Test the web application
   cd web
   npm run lint
   ```
5. Ensure all tests pass and the code is properly formatted
6. Commit your changes with a descriptive message following this format:

   For changes that need to be included in the changelog (excluding docs or chore changes), use the `fix` or `feat` format with a specific scope:
   ```
   fix(scanner): resolve false positive in reentrancy detection
   
   feat(detector): add support for flash loan vulnerability detection
   ```

   For core library changes that don't have a specific detector or scope, you can use `fix` and `feat` without a scope:
   ```
   fix: resolve memory leak in AST parsing
   
   feat: add support for recursive directory scanning
   ```

   For documentation changes, use `docs`:
   ```bash
   docs: improve vulnerability detection explanation
   docs: fix typos in API reference
   ```
   
   For changes that refactor or don't change the functionality, use `chore`:
   ```bash
   chore(refactor): reorganize detector modules
   chore: update dependencies to latest versions
   ```

   Each commit message should be clear and descriptive, explaining what the change does. For features and fixes, include context about what was added or resolved.

7. Push your branch to your fork
8. Open a pull request against the **main** branch. In your PR description:
   - Clearly describe what changes you made and why
   - Include any relevant context or background
   - List any breaking changes or deprecations
   - Add screenshots for UI changes
   - Reference related issues or discussions

## Testing 

All contributions must include appropriate tests. Follow these guidelines: 

- Write unit tests for new features (use `cargo test` for Rust code)
- Test new vulnerability detectors with appropriate test contracts in `/core/contracts`
- Ensure all tests pass before submitting a pull request (`cargo test` and `make verify`)
- Update existing tests if your changes affect their behavior
- Follow the existing test patterns and structure
- For detector changes, verify both vulnerable and safe patterns are correctly identified
- Test with different Solidity contract patterns when applicable (e.g., modern DeFi patterns, proxy contracts)

## Pull Request Process

1. Create a draft pull request early to facilitate discussion
2. Reference any related issues in your PR description (e.g., 'Closes #123')
3. Ensure all tests pass and the build is successful:
   - Core scanner: `cargo test` and `make verify`
   - Web application: `npm run lint` and `npm run build`
4. Update documentation as needed (README, contract test documentation, etc.)
5. Keep your PR focused on a single feature or bug fix
6. Be responsive to code review feedback
7. For user-facing changes (new detectors, API changes), update relevant documentation

## Code Style

**General Principles:**
- Follow the existing code style in both Rust and TypeScript codebases
- Keep functions small and focused
- Use meaningful variable and function names
- Add comments for complex logic, especially vulnerability detection algorithms
- Update relevant documentation when making API changes

**Rust Code (Core Scanner):**
- Follow Rust naming conventions (snake_case for functions/variables, PascalCase for types)
- Use `cargo fmt` to format code before committing
- Leverage Rust's type system and pattern matching
- Prefer functional programming patterns where appropriate
- Document public APIs with doc comments

**TypeScript/JavaScript Code (Web Application):**
- Use TypeScript types and interfaces effectively
- Follow Next.js conventions (Server Components by default, explicit 'use client' for client components)
- Use ESLint rules (run `npm run lint` before committing)
- Prefer functional components and hooks over class components
- Follow React best practices and Next.js App Router patterns

## Component-Specific Guidelines

### Core Scanner (`/core`)

- When adding new vulnerability detectors, include test contracts in `/core/contracts`
- Document detector logic and confidence scoring rationale
- Ensure detectors handle edge cases and false positive reduction
- Update test contracts when adding new vulnerability patterns

### Web Application (`/web`)

- Follow Next.js App Router conventions
- Use Server Components by default, mark client components explicitly
- Ensure UI components are accessible and responsive
- Test scanner integration with various contract sizes and formats

### Documentation (`/docs`)

- Keep documentation up-to-date with code changes
- Use clear, concise language
- Include code examples for common use cases (scanning contracts, interpreting results)
- Document detector behavior and confidence levels
- Follow the existing documentation style and structure

## Security Issues

If you discover a security vulnerability in Stealth, please report it responsibly. For detailed information on how to report security issues, please see our [Security Policy](/SECURITY.md).

**Important:** Do not disclose security vulnerabilities publicly until they have been addressed. Include a detailed description of the vulnerability, steps to reproduce it, and any potential impact. All reports will be reviewed and addressed promptly.