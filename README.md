# Relink: Rust ELF Loader and Runtime Linker

<p align="center">
  <img src="docs/assets/logo-dark.svg#gh-dark-mode-only" width="500" alt="Relink">
  <img src="docs/assets/logo.svg#gh-light-mode-only" width="500" alt="Relink">
</p>

<p align="center">
  <a href="https://crates.io/crates/elf_loader"><img src="https://img.shields.io/crates/v/elf_loader.svg" alt="Crates.io"></a>
  <a href="https://crates.io/crates/elf_loader"><img src="https://img.shields.io/crates/d/elf_loader.svg" alt="Crates.io downloads"></a>
  <a href="https://docs.rs/elf_loader"><img src="https://docs.rs/elf_loader/badge.svg" alt="Docs.rs"></a>
  <img src="https://img.shields.io/badge/rust-1.93.0%2B-blue.svg" alt="Minimum supported Rust version">
  <a href="https://github.com/weizhiao/Relink/actions/workflows/rust.yml"><img src="https://github.com/weizhiao/Relink/actions/workflows/rust.yml/badge.svg" alt="Build status"></a>
  <img src="https://img.shields.io/crates/l/elf_loader.svg" alt="MIT/Apache-2.0 license">
</p>

<p align="center">
  <a href="README.md">English</a> | <a href="README_zh.md">简体中文</a>
</p>

<p align="center">
  <strong>Fast · Customizable · no_std support</strong>
</p>

Relink is a Rust ELF loader and runtime linker for plugins, JITs, and custom runtimes. Take control of dependency resolution, symbol binding, memory layout, and the loading lifecycle.

[Quick start](#quick-start) · [Performance](#benchmarks) · [Platforms](#platform-support) · [Examples](examples/README.md) · [API docs](https://docs.rs/elf_loader)

## Highlights

- **Flexible inputs:** load shared libraries, executables, and relocatable objects (`.o` / `.ko`) from files or memory.
- **Control over linking:** customize dependency resolution, symbol scopes, and relocation; observe or intervene in loading through observers.
- **Optimize before loading:** scan before mapping, reorder sections, and group hot code. See [platform support](#platform-support) for architecture coverage.
- **Fit your runtime:** `no_std` support with replaceable mmap and memory-access backends for kernels, embedded systems, or remote memory.

## Benchmarks

Across the 10 system libraries in this run, Relink used **4–32% less load time** and
**about one-third the symbol-hit time** compared with `libloading` 0.9.0 (glibc).
Figures show means and 95% confidence intervals; lower is better.

**Load & teardown · µs**

![Relink and libloading load and teardown times](benches/figures/load-teardown-dark.svg#gh-dark-mode-only)
![Relink and libloading load and teardown times](benches/figures/load-teardown.svg#gh-light-mode-only)

Teardown times are similar overall. Context creation/destruction and host imports are outside timing.

**Symbol lookup · ns**

![Relink and libloading symbol lookup hit and miss times](benches/figures/symbol-lookup-dark.svg#gh-dark-mode-only)
![Relink and libloading symbol lookup hit and miss times](benches/figures/symbol-lookup.svg#gh-light-mode-only)

Symbol lookup compares public APIs: Relink searches root exports, while `dlsym` may also
search dependencies. Misses include each API's error handling.

| Configuration | Value |
| --- | --- |
| Date / commit | 2026-10-29 · `ed37e60` |
| Environment | Ryzen 9 7945HX · Linux 7.0.11-arch1-1 x86_64 · glibc 2.43 · Rust 1.96.0 |
| Sampling | Pinned to CPU 2; 1 s warmup, 2 s measurement, 30 samples per case; warm file cache |

Reproduce with `taskset -c 2 bash ci/bench.sh`. See the [benchmark guide](benches/README.md)
for dependencies and measurement scope.

## Quick Start

```toml
[dependencies]
elf_loader = "0.18.0"
```

Load a shared library, call a function, then release its modules. First
[build the example library](examples/README.md#build-the-example-library), then run
from the repository root. You can also run `cargo run --example linker_load` directly.

```rust
use elf_loader::{LinkContext, Linker, input::PathBuf, linker::SearchPathResolver};
use std::ffi::c_int;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut context = LinkContext::for_process();
    let loaded = Linker::new()
        .with_resolver(SearchPathResolver::new())
        .run()
        .load(&mut context, PathBuf::from("target/example-library/libexample.so"))?;

    // SAFETY: example.c defines int example_add(int, int).
    unsafe {
        let add = context.module(loaded.root())?
            .get::<unsafe extern "C" fn(c_int, c_int) -> c_int>("example_add")?
            .ok_or("missing example_add")?;
        assert_eq!(add(2, 3), 5);
    }
    drop(loaded.release(&mut context)?);
    Ok(())
}
```

More examples: [memory loading](examples/load_from_memory.rs) · [object files](examples/load_object.rs) · [layout changes](examples/linker_scan_first.rs) · [host imports](examples/host_import.rs).

## Platform Support

| Instruction set | Dynamic libraries / executables | Section reordering | `.o` / `ET_REL` |
| --- | --- | --- | --- |
| `x86_64` | ✅ | ✅ | ✅ |
| `x86` | ✅ | 🚧 | 🚧 |
| `aarch64` | ✅ | 🚧 | 🚧 |
| `arm` | ✅ | 🚧 | 🚧 |
| `riscv64` | ✅ | 🚧 | ✅ |
| `riscv32` | ✅ | 🚧 | 🚧 |
| `loongarch64` | ✅ | 🚧 | 🚧 |
| `xtensa` | 🔧 | 🚧 | 🚧 |

✅ Supported · 🔧 Partial support · 🚧 Pending.

Xtensa currently supports dynamic relocation, but not lazy binding or TLS
relocations.

## Feature Flags

The default `full` set enables `libc`, `object`, and `lazy-binding`. For a minimal libc build:

```toml
elf_loader = { version = "0.18.0", default-features = false, features = ["libc"] }
```

<details>
<summary>All feature flags</summary>

| Feature | Default | Purpose |
| --- | --- | --- |
| `libc` | Yes | Use the libc backend on Linux/Android; enable `host::open` on Linux/glibc |
| `lazy-binding` | Yes | Enable the built-in native PLT/GOT lazy binder |
| `object` | Yes | Enable relocatable object (`ET_REL`) loading and `LoaderRun::load_object()` |
| `version` | No | Enable version-aware symbol lookup such as `get_version()` |
| `log` | No | Enable `log` integration for loader and relocation diagnostics |
| `portable-atomic` | No | Support targets without native pointer-sized atomics |
| `use-syscall` | No | Use the Linux syscall backend instead of libc |
| `full` | Yes | Convenience bundle: `lazy-binding`, `object`, `libc` |

</details>

TLS is configured through a resolver, without a feature flag. Host libraries require
explicit imports; see the [example](examples/host_import.rs).

## Contributing

Report problems in [Issues](https://github.com/weizhiao/Relink/issues), or follow the
[contribution guide](CONTRIBUTING.md) to submit improvements.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

## Contributors

<a href="https://github.com/weizhiao/Relink/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=weizhiao/Relink" alt="Project contributors">
</a>
