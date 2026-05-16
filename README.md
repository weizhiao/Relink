# Relink: Rust ELF Loader and Runtime/JIT Linker

<p align="center">
  <img src="https://raw.githubusercontent.com/weizhiao/elf_loader/main/docs/imgs/logo.svg" width="560" alt="Relink logo">
</p>

<p align="center">
  <a href="https://crates.io/crates/elf_loader"><img src="https://img.shields.io/crates/v/elf_loader.svg" alt="Crates.io"></a>
  <a href="https://crates.io/crates/elf_loader"><img src="https://img.shields.io/crates/d/elf_loader.svg" alt="Crates.io downloads"></a>
  <a href="https://docs.rs/elf_loader"><img src="https://docs.rs/elf_loader/badge.svg" alt="Docs.rs"></a>
  <img src="https://img.shields.io/badge/rust-1.93.0%2B-blue.svg" alt="Minimum supported Rust version">
  <a href="https://github.com/weizhiao/elf_loader/actions/workflows/rust.yml"><img src="https://github.com/weizhiao/elf_loader/actions/workflows/rust.yml/badge.svg" alt="Build status"></a>
  <img src="https://img.shields.io/crates/l/elf_loader.svg" alt="MIT/Apache-2.0 license">
</p>

<p align="center">
  <a href="README.md">English</a> | <a href="README_zh.md">简体中文</a> |
  <a href="CONTRIBUTING.md">Contributing</a> | <a href="CONTRIBUTING_zh.md">贡献指南</a>
</p>

<p align="center">
  <strong>Rust no_std ELF loader, runtime linker, and JIT linker with dynamic link-time optimization.</strong>
</p>

Relink loads ELF images from files or memory and performs dynamic loading, dependency resolution, relocation, and symbol lookup. It fits plugin systems, JIT and hot-reload flows, isolated link contexts, scan-first layout optimization, kernels, and embedded runtimes when `dlopen` is too rigid.

## Use Cases

- Load plugins, JIT artifacts, or hot-update modules at runtime with custom dependency resolution and symbol scopes.
- Scan dependencies and sections before mapping, then use `--emit-relocs` to reorder layout, pack hot code, use huge pages, or run custom passes.
- Keep ELF scanning, mapping, and relocation available in `no_std`, kernel, embedded, or custom mmap environments.
- Scan, rewrite, and load images with different ELF layouts, ABIs, or target architectures.
- Compose shared objects, executable images, and relocatable objects in one loading flow.

## What It Loads

- Shared objects / dynamic libraries (`ET_DYN`)
- Executables and PIE-style images (`ET_EXEC`, plus executable-style `ET_DYN`)
- Relocatable object files (`ET_REL`) when the `object` feature is enabled
- File-backed or in-memory inputs via `&str`, `String`, `&[u8]`, `Vec<u8>`, `ElfFile`, and `ElfBinary`

Use `Loader::load()` when you want automatic ELF type detection. Use `load_dylib()`, `load_exec()`, or `load_object()` when you want strict type checks.

## Core Capabilities

| Capability | What Relink provides |
| --- | --- |
| In-memory loading | Load ELF images from paths, memory buffers, or parsed inputs |
| Custom linking policy | Caller-controlled `DT_NEEDED` resolution, symbol lookup order, scopes, and relocation interception |
| Isolated link contexts | Multiple `LinkContext`s keep independent module stores, dependency graphs, and symbol scopes |
| Scan-first planning | Scan dependencies and sections first, then adjust layout, materialization, or section data before mapping |
| Dynamic link-time optimization | With `--emit-relocs`, reorder sections, pack hot code, and run custom passes |
| Replaceable mapping backend | Plug in platform-specific mmap, permission, page-size, or huge-page policies |
| Type-safe symbol access | Symbol handles are tied to the lifetime of their loaded image, reducing dangling-symbol risks |
| Hybrid linking | Compose `.so`, executable images, and feature-gated `.o` / `ET_REL` inputs |

### Compared With `dlopen`

| Capability | Relink | `dlopen`-style loading |
| --- | --- | --- |
| In-memory loading | ✅ Paths / memory buffers / parsed ELF | ❌ |
| `ET_REL` loading | ✅ Feature-gated | ❌ |
| Pre-link planning | ✅ Dependencies / sections / mapping strategy | ❌ |
| Dynamic link-time optimization | ✅ Section reordering / hot-code packing / custom passes | ❌ |
| Mapping policy | ✅ Replaceable mmap backend, page size, and huge-page policy | ❌ |
| Dependency and symbol policy | ✅ Dependency graph / scope / lookup / interception control | ❌ |
| Context isolation | ✅ Multiple `LinkContext`s isolate dependency graphs and symbol scopes | ❌ |
| Heterogeneous loading | ✅ Different ELF layouts / ABIs / target architectures | ❌ |

## Quick Start

The default feature set is suitable for loading dynamic libraries, executables, and handling TLS:

```toml
[dependencies]
elf_loader = "0.15.0"
```

To enable the common advanced features in one bundle:

```toml
[dependencies]
elf_loader = { version = "0.15.0", features = ["full"] }
```

### Load a Dynamic Library and Call a Symbol

```rust
use elf_loader::{
    image::{SyntheticModule, SyntheticSymbol},
    Loader, Result,
};

extern "C" fn host_double(value: i32) -> i32 {
    value * 2
}

fn main() -> Result<()> {
    let lib = Loader::new()
        .load_dylib("path/to/plugin.so")?
        .relocator()
        .scope([SyntheticModule::new(
            "__host",
            [SyntheticSymbol::function("host_double", host_double as *const ())],
        )])
        .relocate()?;

    let run = unsafe {
        lib.get::<extern "C" fn(i32) -> i32>("run")
            .expect("symbol `run` not found")
    };
    assert_eq!(run(21), 42);

    Ok(())
}
```

## Loading Paths

| Path | Entry point | Best for |
| --- | --- | --- |
| Direct loading | `Loader::load_dylib()` / `load_exec()` / `load_object()` | You already know which image to load and only need scopes, TLS, lazy binding, or relocation hooks |
| Runtime dependency linking | `Linker::load()` | Use `KeyResolver` and `LinkContext` to manage dependency graphs, scopes, and context isolation |
| Scan-first linking | `Linker::load_scan_first()` | Discover `DT_NEEDED` dependencies first, then run layout passes, choose materialization policy, and relocate as one group |
| Relocatable objects | `Loader::load_object()` | Compose `.o` and `.so` inputs at runtime; requires the `object` feature |
| Custom mapping environment | `Loader::with_mmap()` / `with_page_size()` | Plug in custom mmap, permission, page-size, or huge-page policies |

## Advanced Capability Index

| Topic | Entry point / example |
| --- | --- |
| Load from memory | `ElfBinary::new(name, bytes)`, or direct `load_dylib(&bytes)` / `load_exec(&bytes)` |
| Host symbols and scopes | `SyntheticModule`, `scope()`, `extend_scope()` |
| Relocation interception | `pre_handler()`, `post_handler()`, see `cargo run --example relocation_handler` |
| Lazy binding | `relocator().lazy()`, requires the `lazy-binding` feature |
| Runtime dependency graphs | `KeyResolver`, `LinkContext`, `Linker::load()` |
| Pre-map layout optimization | `Linker::load_scan_first()`, `map_pipeline()`, see `cargo run --example linker_scan_first` |
| Relocatable objects | `cargo run --example load_object --features object` |
| Lifecycle callbacks | `cargo run --example lifecycle` |

Dynamic link-time layout optimization usually requires the target ELF to retain relocation information, for example by passing `-Wl,--emit-relocs` to the linker. Scan-first passes can inspect sections, modify data, adjust materialization, and place code, read-only data, writable data, or TLS into different arenas before mapping.

## Benchmarks

The table below is a GitHub Actions snapshot, not a universal performance claim. It is meant as a reproducible reference point for the current benchmark suite; run `cargo bench` on your target environment for numbers that matter to your workload. Full environment details are in [actions/runs/25632675040/job/75239090388](https://github.com/weizhiao/Relink/actions/runs/25632675040/job/75239090388), and the fixture is the repository's `libc -> libb -> liba` test chain, not the system C library.

Lower is better for loading. `scan_first` includes dependency scanning and section-region planning, so it is a planning-path cost rather than a direct `dlopen` replacement.

| Benchmark | Time | Relative time |
| --- | ---: | --- |
| `elf_loader/memory` | `89.531 µs` | `0.78x` |
| `elf_loader/file` | `101.01 µs` | `0.88x` |
| `linker/runtime` | `111.32 µs` | `0.97x` |
| `libloading/lazy` | `115.34 µs` | `1.00x` |
| `libloading/now` | `115.77 µs` | `1.00x` |
| `linker/scan_first` | `288.92 µs` | `2.51x` |

Symbol lookup was measured after both loaders had already loaded the fixture chain:

| Benchmark | Time | Relative time |
| --- | ---: | --- |
| `symbol/elf_loader/hit` | `10.280 ns` | `0.13x` |
| `symbol/libloading/hit` | `80.154 ns` | `1.00x` |
| `symbol/elf_loader/miss` | `11.548 ns` | `0.03x` |
| `symbol/libloading/miss` | `375.49 ns` | `1.00x` |

## Feature Flags

| Feature | Default | Purpose |
| --- | --- | --- |
| `libc` | Yes | Use the libc backend on Unix-like platforms |
| `tls` | Yes | Enable TLS relocation handling and the built-in TLS resolver |
| `lazy-binding` | No | Enable PLT/GOT lazy binding and lazy-fixup lookup configuration |
| `object` | No | Enable relocatable object (`ET_REL`) loading and `Loader::load_object()` |
| `version` | No | Enable version-aware symbol lookup such as `get_version()` |
| `log` | No | Enable `log` integration for loader and relocation diagnostics |
| `portable-atomic` | No | Support targets without native pointer-sized atomics |
| `use-syscall` | No | Use the Linux syscall backend instead of libc |
| `full` | No | Convenience bundle: `tls`, `lazy-binding`, `object`, `libc` |

Notes:

- The default features are `tls` + `libc`.
- Compiling with `tls` is not enough by itself for TLS-using modules. Start from `Loader::new().with_default_tls_resolver()` or provide your own TLS resolver when loading ELF objects that require TLS relocations.
- `load_object()` is feature-gated. `cargo run --example load_object` will fail under the default feature set unless you add `--features object`.

## Examples

The [`examples/`](examples/) directory covers the main extension points:

| Example | What it demonstrates | Command |
| --- | --- | --- |
| `load_dylib` | Load shared objects and resolve host symbols | `cargo run --example load_dylib` |
| `linker_load` | Resolve `DT_NEEDED` dependencies with `Linker::load()` | `cargo run --example linker_load` |
| `from_memory` | Load ELF data from a byte buffer | `cargo run --example from_memory` |
| `load_exec` | Inspect executable entry and base addresses | `cargo run --example load_exec` |
| `load_hook` | Observe segment loading with `with_hook()` | `cargo run --example load_hook` |
| `linker_scan_first` | Discover `DT_NEEDED`, run scan-first passes, and configure pre-map layout | `cargo run --example linker_scan_first` |
| `lifecycle` | Custom `.init` / `.fini` handling | `cargo run --example lifecycle` |
| `user_data` | Initialize dynamic-image metadata | `cargo run --example user_data` |
| `relocation_handler` | Intercept relocations with a custom handler | `cargo run --example relocation_handler` |
| `load_object` | Load relocatable object files | `cargo run --example load_object --features object` |

## Platform Notes

| Architecture | Dynamic libraries / executables | Dynamic link-time optimization | `.o` / `ET_REL` |
| --- | --- | --- | --- |
| `x86_64` | ✅ Primary validation path | ✅ Layout passes / placement / hot code / huge-page arenas | ✅ `object` feature |
| `x86` / `aarch64` / `arm` / `riscv64` / `riscv32` / `loongarch64` | ✅ | 🟡 Basic dependency planning; complex reordering pending | ⏳ Pending |

Legend: ✅ supported, 🟡 basic support, ⏳ pending. Complex section-reorder repair and `.o` / `ET_REL` support are currently centered on `x86_64` relocation handling; contributions for the other architectures are welcome.

Symbol lookup is name-based and does not perform Rust name mangling for you. Export C ABI symbols when you want stable runtime lookup names.

## Contributing

Issues and pull requests are welcome, especially around platform support, examples, and diagnostics. Star the project if it is useful in your work.

## License

This project is dual-licensed under either of the following:

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

## Contributors

<a href="https://github.com/weizhiao/elf_loader/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=weizhiao/elf_loader" alt="Project contributors">
</a>
