# Relink: Rust ELF Loader and Runtime Linker

<p align="center">
  <img src="https://raw.githubusercontent.com/weizhiao/elf_loader/main/docs/assets/logo.svg" width="560" alt="Relink logo">
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
  <strong>Load, link, and rewrite ELF in Rust and no_std environments.</strong>
</p>

Relink is a Rust ELF loading and runtime linking library. It can load `.so` files, executables, and object files from disk or memory, then resolve dependencies, apply relocations, and look up symbols.

## When To Use It

- Load plugins, JIT artifacts, or hot-reload modules at runtime.
- Control `DT_NEEDED` dependencies, symbol scopes, or relocation handling yourself.
- Load ELF from memory, or plug in your own mmap or memory-management backend.
- Scan dependencies and sections first, then reorder layout, pack hot code, use huge pages, or run custom handling.
- Load relocatable ELF files such as `.o` / `.ko`.
- Keep ELF loading available in `no_std`, kernels, embedded systems, or non-standard runtimes.

## What It Loads

- Shared objects / dynamic libraries (`ET_DYN`)
- Executables and PIE-style images (`ET_EXEC`, plus executable-style `ET_DYN`)
- Relocatable object files (`ET_REL`, for example `.o` / `.ko`) when the `object` feature is enabled

## Compared With `dlopen`

| Capability | Relink | `dlopen`-style loading |
| --- | --- | --- |
| In-memory loading | ✅ Load from paths, byte buffers, or already parsed ELF inputs | ❌ |
| `ET_REL` loading | ✅ Load and relocate `.o` / `.ko` / `ET_REL` files | ❌ |
| Pre-link planning | ✅ Resolve dependencies and sections first, then decide how to map | ❌ |
| Pre-load layout optimization | ✅ Adjust section layout before mapping for hot-code packing or custom reordering | ❌ |
| Mapping policy | ✅ Replace mmap, page size, permissions, and memory-access backends | ❌ |
| Dependency and symbol policy | ✅ Customize `DT_NEEDED` resolution, symbol scopes, and relocation interception | ❌ |
| Context isolation | ✅ Multiple `LinkContext`s keep independent modules, dependency graphs, and symbol scopes | ❌ |
| Remote / heterogeneous loading | ✅ Use custom memory access to load remote devices or heterogeneous target ELFs locally | ❌ |

## Quick Start

The default feature set is suitable for loading dynamic libraries, executables, and handling TLS:

```toml
[dependencies]
elf_loader = "0.15.1"
```

To enable the common advanced features in one bundle:

```toml
[dependencies]
elf_loader = { version = "0.15.1", features = ["full"] }
```

### Use Linker to Load Dependencies

```rust
use elf_loader::{
    Result,
    input::PathBuf,
    linker::{LinkContext, Linker, SearchPathResolver},
};

fn main() -> Result<()> {
    let root = PathBuf::from("path/to/plugin.so");
    let mut context: LinkContext<PathBuf, ()> = LinkContext::new();

    let loaded = Linker::new()
        .resolver(SearchPathResolver::new())
        .load(&mut context, root)?;

    let run = unsafe {
        loaded
            .get::<extern "C" fn() -> i32>("run")
            .expect("symbol `run` not found")
    };
    let _ = run();

    Ok(())
}
```

## Benchmarks

The table below is a GitHub Actions performance snapshot. Use it only as a reference for the current test suite. Full environment details are in [actions/runs/25632675040/job/75239090388](https://github.com/weizhiao/Relink/actions/runs/25632675040/job/75239090388). The fixture is the repository's `libc -> libb -> liba` test chain, not the system C library.

Lower is better for loading. `scan_first` includes dependency scanning and section planning, so it is not a direct `dlopen` replacement.

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
| `tls` | Yes | Enable the built-in same-process TLS resolver |
| `lazy-binding` | No | Enable PLT/GOT lazy binding and lazy-fixup lookup configuration |
| `object` | No | Enable relocatable object (`ET_REL`) loading and `Loader::load_object()` |
| `version` | No | Enable version-aware symbol lookup such as `get_version()` |
| `log` | No | Enable `log` integration for loader and relocation diagnostics |
| `portable-atomic` | No | Support targets without native pointer-sized atomics |
| `use-syscall` | No | Use the Linux syscall backend instead of libc |
| `full` | No | Convenience bundle: `tls`, `lazy-binding`, `object`, `libc` |

Notes:

- The default features are `tls` + `libc`.
- `tls` only provides the default resolver; custom TLS resolvers do not need this feature.
- `load_object()` is feature-gated. `cargo run --example load_object` will fail under the default feature set unless you add `--features object`.

## Platform Support

| Instruction set | Dynamic libraries / executables | Pre-load layout optimization | `.o` / `ET_REL` |
| --- | --- | --- | --- |
| `x86_64` | ✅ | ✅ | ✅ |
| `x86` | ✅ | 🟡 | ⏳ |
| `aarch64` | ✅ | 🟡 | ⏳ |
| `arm` | ✅ | 🟡 | ⏳ |
| `riscv64` | ✅ | 🟡 | ✅ |
| `riscv32` | ✅ | 🟡 | ⏳ |
| `loongarch64` | ✅ | 🟡 | ⏳ |

Legend: ✅ supported, 🟡 basic support, ⏳ pending. Complex section-reorder repair and `.o` / `ET_REL` support are currently centered on `x86_64` and `riscv64` relocation handling; contributions for the other architectures are welcome.

## Contributing

Issues and pull requests are welcome. Star the project if it is useful in your work.

## License

This project is dual-licensed under either of the following:

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

## Contributors

<a href="https://github.com/weizhiao/elf_loader/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=weizhiao/elf_loader" alt="Project contributors">
</a>
