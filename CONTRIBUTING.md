# Contributing to RustCrypt

First off, thank you for considering contributing to RustCrypt! 🎉

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Cross-Language Compatibility Rules](#cross-language-compatibility-rules)
- [Pull Request Process](#pull-request-process)
- [Style Guidelines](#style-guidelines)

---

## Code of Conduct

This project and everyone participating in it is governed by our commitment to providing a welcoming and inclusive environment. Please be respectful and constructive in all interactions.

---

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs **actual behavior**
- **Rust version** (`rustc --version`) and crate version
- **Operating system** and architecture
- **Code samples** if applicable (never include real passwords or secrets)

### 💡 Suggesting Features

Feature requests are welcome! Please include:

- **Clear description** of the feature
- **Use case** - why would this be useful?
- **Possible implementation** approach (optional)
- Whether the change affects the wire format (see below)

### 🔧 Pull Requests

1. Fork the repo and create your branch from `main`
2. Add tests for any new behaviour
3. Make sure the full gate passes (see below)
4. Update the documentation (`README.md`, rustdoc, `CHANGELOG.md`)

---

## Development Setup

```bash
git clone https://github.com/farizfadian/rustcrypt.git
cd rustcrypt

# Full gate (this is what CI runs)
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo clippy --all-targets --no-default-features --locked -- -D warnings
cargo test --all-features --locked
cargo test --no-default-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
cargo build --no-default-features --locked
```

MSRV is Rust 1.75; check it with `rustup toolchain install 1.75.0` and
`cargo +1.75.0 check --all-targets --all-features --locked`. `Cargo.lock` is
committed and pinned to MSRV-compatible versions; if you need to update
dependencies run `cargo generate-lockfile --config 'resolver.incompatible-rust-versions="fallback"'`
and re-run the MSRV check.

Optional but recommended for anything touching encryption:

```bash
# Live round trips with the Go reference implementation
go install github.com/farizfadian/gocrypt/cmd/gocrypt-cli@latest
cargo test --test cross_language -- --ignored

# Round trips against every sibling CLI found on PATH
powershell -ExecutionPolicy Bypass -File scripts/cross-check.ps1
```

---

## Cross-Language Compatibility Rules

RustCrypt is one of five libraries (GoCrypt, PyCrypt, NodeCrypt, PHPCrypt, RustCrypt) that must all read each other's `ENC(...)` values. **GoCrypt is the reference implementation.**

- Never change a wire format (salt/nonce layout, KDF, padding, base64 alphabet, defaults) unless the change is coordinated across all five libraries. Even a "fix" that makes RustCrypt closer to Java Jasypt breaks the family if the others do not change at the same time.
- Any PR touching `src/kdf.rs`, `src/encryptor.rs` or `src/jasypt.rs` must keep `tests/cross_language.rs` and `src/golden.rs` green. Those tests compare against vectors produced by GoCrypt itself.
- If you regenerate `tests/fixtures/gocrypt_vectors.json`, use `scripts/gen-vectors` and record the GoCrypt commit in the fixture.
- Keep error messages and CLI behaviour aligned with `gocrypt-cli` where practical.

---

## Pull Request Process

1. Ensure the full gate above passes locally
2. Update `CHANGELOG.md` under `[Unreleased]`
3. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`)
4. The PR will be merged once it passes CI and review

---

## Style Guidelines

- `cargo fmt` formatting, `cargo clippy -- -D warnings` clean
- Public items need rustdoc with an example where it helps (`#![warn(missing_docs)]` is on)
- No `unsafe` outside `ConfigLoader::set_to_env` (`#![deny(unsafe_code)]` is on)
- Pure Rust only: no OpenSSL or other C dependencies
- Tests: unit tests next to the code, behaviour tests under `tests/`, examples must compile and run

Thank you for contributing! ❤️
