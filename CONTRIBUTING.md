# Contributing to Relink

Thanks for your interest in contributing to Relink. Contributions of all sizes are welcome, including bug reports, documentation improvements, examples, tests, refactors, and new features.

This document describes the general contribution workflow for the project.

## Ways to Contribute

You can help by:

- reporting bugs or unclear behavior
- improving documentation or examples
- adding tests or benchmarks
- fixing issues labeled `good first issue`
- proposing or implementing new features
- improving portability, safety, or performance

## Before You Start

For small fixes, feel free to open a pull request directly.

For larger changes, please open an issue first so we can align on scope and design before implementation. This is especially helpful for:

- public API changes
- loader behavior changes
- feature-flag changes
- large refactors
- cross-platform or `no_std` behavior changes

Before opening a new issue or pull request, please check whether the topic has already been discussed.

## Development Setup

Relink uses stable Rust for regular development. The current minimum supported Rust version is `1.93.0`.

Typical setup:

```bash
rustup toolchain install stable
cargo test
```

Some CI jobs also use nightly or cross targets. You usually do not need to run every CI configuration locally unless your change touches those areas directly.

## Recommended Workflow

1. Fork the repository and create a topic branch from `main`.
2. Keep the change focused. Small, reviewable pull requests are preferred.
3. Add or update tests when behavior changes.
4. Update documentation when the public API, examples, or user-facing behavior changes.
5. Run formatting and relevant tests locally.
6. Open a pull request with a clear description of the change and why it is needed.

## Local Checks

At a minimum, please run:

```bash
cargo fmt --all
cargo test
```

If your change touches feature-gated code, also run:

```bash
cargo test --features full
```

If you changed platform-specific code or workspace crates, running additional checks is appreciated when practical. For example:

```bash
cargo run -p windows-elf-loader --example from_memory
```

Notes:

- The `mini-loader` crate is exercised in CI with a nightly toolchain and a `no_std` target.
- Cross-target validation is primarily handled by CI.

## Coding Guidelines

Please try to match the existing style of the codebase:

- prefer focused changes over unrelated cleanup
- keep public APIs clear and well-documented
- preserve existing behavior unless the change intentionally adjusts it
- add tests for bug fixes and behavior changes when possible
- keep examples and docs in sync with code changes

This project contains low-level loader logic and `unsafe` code. When touching unsafe code:

- keep the change narrowly scoped
- explain important invariants in code comments when needed
- describe the safety reasoning in the pull request

## Commit Messages

Conventional Commit-style messages are recommended and match the current history well. Examples:

- `fix(loader): reject malformed program header tables`
- `refactor(elf): wrap ELF metadata with semantic types`
- `docs(readme): clarify lazy binding workflow`

This is recommended rather than strictly required, but it helps keep history readable.

## Pull Request Checklist

Before opening a pull request, please check that:

- the change is based on the latest `main` branch
- the pull request has a clear title and description
- relevant tests pass locally
- documentation and examples are updated if needed
- unrelated formatting or refactoring is not mixed into the same change

## Review Process

Reviews may ask for:

- narrower scope
- clearer tests
- updated documentation
- safer handling of low-level or platform-specific behavior

Please do not worry if feedback asks for iteration. That is a normal part of the process.

## Reporting Bugs

Bug reports are most helpful when they include:

- the target platform
- Rust version
- enabled feature flags
- a minimal reproduction or failing example
- expected behavior and actual behavior

## License

By contributing to this repository, you agree that your contributions will be licensed under the same terms as the project: MIT OR Apache-2.0.
