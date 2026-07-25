# Examples

The examples are grouped by the API or workflow they demonstrate.

## Loading

| Example | Description |
| --- | --- |
| `load_dylib` | Load and relocate dependent shared libraries |
| `load_exec` | Load an ELF executable and inspect its entry point |
| `load_object` | Load relocatable object files; requires the `object` feature |
| `load_from_memory` | Load a shared library from an in-memory byte buffer |

Run an example from the repository root:

```sh
cargo run --example load_dylib
```

## Linking

| Example | Description |
| --- | --- |
| `linker_load` | Resolve and load a shared library with its dependencies |
| `linker_scan_first` | Plan section placement before mapping images |

## Observers

The `observer` example combines load, symbol binding, lifecycle, and user-data
hooks:

```sh
cargo run --example observer
```

## Cross-Target

[`xtensa-qemu`](xtensa-qemu) is a standalone crate because it uses an
Espressif-specific Rust toolchain, target configuration, and QEMU runtime. Its
README contains the environment setup and one-command runner.

The `support` directory contains fixtures shared by examples, tests, and
benchmarks; it is not part of the public example API.
