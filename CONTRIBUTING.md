# Contributing to Relink

Bug reports, documentation, examples, tests, and code changes are welcome.
For small fixes, open a pull request directly. For public API changes, major
refactors, or changes to loading and platform behavior, open an issue first to
discuss scope and design. Check existing issues and pull requests before starting.

## Development

Use stable Rust, version 1.93.0 or later. Run commands from the repository root:

```sh
cargo fmt --all --check
cargo test
cargo test --doc --features "full version log portable-atomic"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --features "full version log portable-atomic"
```

The default features already include `full`. Check additional configurations
when your change affects them:

```sh
cargo check --no-default-features
cargo check --no-default-features --features use-syscall
```

`use-syscall` and `std` are mutually exclusive, so `--all-features` is not a valid
configuration. See [test layers](tests/README.md) and [examples](examples/README.md)
for fixtures and setup. Cross-target checks and the nightly `mini-loader` build
are covered by CI; run the relevant jobs locally when changing those components.

## Pull Requests

1. Create a topic branch from `main` and keep the change focused.
2. Update tests for behavior changes, and documentation for public API changes.
3. Explain the problem, resulting behavior, and validation in the PR description.
   For unsafe code, document the invariants and safety reasoning.

Match the existing code style and keep unrelated refactors out of the change.
Conventional Commit messages are welcome, for example
`fix(loader): reject malformed program header tables`.

## Bug Reports

Include the target platform, Rust version, enabled features, a minimal
reproduction, and the expected and actual behavior.

## License

Contributions are licensed under the project's MIT OR Apache-2.0 terms.
