# Relink: ELF Loading and Dynamic Link-Time Optimization

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
  <a href="README.md">English</a> | <a href="README_zh.md">简体中文</a>
</p>

<p align="center">
  <a href="CONTRIBUTING.md">Contributing</a> | <a href="CONTRIBUTING_zh.md">贡献指南</a>
</p>

<p align="center">
  <strong>Dynamic link-time optimization, heterogeneous loading, and deep customization.</strong><br>
</p>

Relink is a high-performance, no_std-friendly ELF loader and runtime/JIT linker for Rust. It loads ELF images from files or memory, performs runtime relocation and symbol resolution, and supports plugin systems, hot reload, kernels, embedded runtimes, and custom dynamic linking policies.

## Use Cases

| Use case | What Relink is built to handle |
| --- | --- |
| Plugin systems, JITs, hot reload | Runtime loading, symbol resolution, and dependency-graph policy without being locked into the fixed `dlopen` flow |
| High-performance server applications | With linker `--emit-relocs` enabled, rewrite section layout before mapping, pack hot code into tighter runtime regions, run custom dynamic link-time optimization passes, and use huge-page mappings to reduce address-translation overhead |
| Kernels, embedded loaders, `no_std` runtimes | Keep ELF scanning, mapping, and relocation available in constrained environments |
| Heterogeneous loading | Scan, rewrite, and load images with different ELF layouts, ABIs, or target architectures from a host runtime |
| Deeply customized linking policy | Compose dependency resolution and relocation interception into your own loading flow |

When `dlopen` is too rigid, and maintaining hand-written dependency resolution, layout optimization, and relocation logic would be too costly, Relink provides a composable alternative.

## What It Loads

- Shared objects / dynamic libraries (`ET_DYN`)
- Executables and PIE-style images (`ET_EXEC`, plus executable-style `ET_DYN`)
- Relocatable object files (`ET_REL`) when the `object` feature is enabled
- File-backed or in-memory inputs via `&str`, `String`, `&[u8]`, `&Vec<u8]`, `ElfFile`, and `ElfBinary`

If you want automatic ELF type detection, use `Loader::load()`. If you want strict type checks, use `load_dylib()`, `load_exec()`, or `load_object()`.

## Core Capabilities

| Capability | What Relink provides |
| --- | --- |
| Dynamic link-time optimization | Scan dependencies and sections first, then run passes before mapping; with `--emit-relocs`, callers can reorder layout, pack hot code, and run custom optimizations |
| Custom dependency and symbol policy | Caller-controlled `DT_NEEDED` resolution, symbol lookup order, symbol interception, and runtime scopes |
| Isolated link contexts | Each `LinkContext` is an independent module repository, dependency graph, and relocation scope; sharing is explicit through `snapshot()` or `extend()` |
| Section-level layout planning | For modules with reorder-repair support, assign section placement / arena before mapping, then choose final runtime mapping by memory class, page size, and sharing policy |
| Heterogeneous and low-level loading | Scan and load images with different ELF layouts, ABIs, or target architectures while keeping a `no_std`-friendly core |
| Type-safe symbol access | Typed symbol handles are tied to the lifetime of their loaded image, reducing dangling-symbol risks |
| Hybrid linking | Compose shared objects, executable images, and relocatable objects in one runtime loading flow |
| Replaceable mapping backend | Let callers plug in platform-specific mmap, permission, and huge-page strategies |

### Compared With Typical Approaches

| Capability | Relink | `dlopen`-style loading |
| --- | --- | --- |
| In-memory loading | Supported: paths, memory buffers, and parsed ELF inputs | Usually awkward or unavailable |
| `ET_REL` loading | Supported: feature-gated relocatable object loading | Not supported |
| Pre-link planning | Supported: scan dependencies and sections first, then decide mapping, arena, page size, and relocation strategy | Not supported |
| Dynamic link-time optimization | Supported: use `--emit-relocs` for section reordering, hot-code packing, and custom passes | Not supported |
| Huge pages and mapping policy | Supported: mapping backends can provide huge pages, permissions, and platform-specific behavior | Usually not caller-controlled |
| Dependency and symbol policy | Supported: caller controls dependency graphs, scopes, symbol lookup, and relocation interception | Usually not caller-controlled |
| Link-context isolation | Supported: multiple `LinkContext`s can hold isolated dependency graphs and symbol scopes | Usually tied to process-global linker state |
| Heterogeneous loading | Supported: scan and load images with different ELF layouts, ABIs, or target architectures | Depends on the host platform dynamic linker |
| Symbol lifetime safety | Supported: typed symbols are lifetime-bound to loaded images | Not supported |

## Quick Start

The default feature set is suitable for loading dynamic libraries, executables, and handling TLS:

```toml
[dependencies]
elf_loader = "0.14.1"
```

To enable the common advanced features in one bundle:

```toml
[dependencies]
elf_loader = { version = "0.14.1", features = ["full"] }
```

### Load a Dynamic Library and Call a Symbol

```rust
use elf_loader::{Loader, Result};

extern "C" fn host_double(value: i32) -> i32 {
    value * 2
}

fn main() -> Result<()> {
    let lib = Loader::new()
        .load_dylib("path/to/plugin.so")?
        .relocator()
        .pre_find_fn(|name| {
            if name == "host_double" {
                Some(host_double as *const ())
            } else {
                None
            }
        })
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
| Direct loading | `Loader::load_dylib()` / `load_exec()` / `load_object()` | You already know which image to load and only need custom symbol lookup, scopes, TLS, lazy binding, or relocation hooks |
| Runtime dependency linking | `Linker::load()` | Use `KeyResolver` and `LinkContext` to manage dependency graphs, scopes, and context isolation without pre-map layout passes |
| Scan-first linking | `Linker::load_scan_first()` | Discover `DT_NEEDED` dependencies first, then run layout passes, choose materialization policy, and relocate as one planned group |
| Relocatable objects | `Loader::load_object()` | Compose `.o` and `.so` inputs at runtime; requires the `object` feature |
| Custom mapping environment | `Loader::with_mmap()` / `with_page_size()` | Plug in custom mmap, permission, page-size, or huge-page policies |

The direct path is shorter and fits plugin or tooling workflows. `Linker::load()` fits runtime loading that needs isolated dependency graphs and scopes. The scan-first path is better for servers, runtimes, and kernels that need to plan before mapping.

## Typical Workflows

### Load from Memory

```rust
use elf_loader::{input::ElfBinary, Loader, Result};

fn main() -> Result<()> {
    let bytes = std::fs::read("path/to/plugin.so").unwrap();

    let lib = Loader::new()
        .load_dylib(ElfBinary::new("plugin.so", &bytes))?
        .relocator()
        .relocate()?;

    println!("loaded {} at 0x{:x}", lib.name(), lib.base());
    Ok(())
}
```

`load_dylib(&bytes)` and `load_exec(&bytes)` also work if you do not need a custom display name.

### Host Symbols, Scopes, and Lazy Binding

The relocation stage can use caller-provided symbol policy:

- `pre_find_fn()` / `post_find_fn()`: inject host symbols before or after looking up symbols inside the target image.
- `scope()` / `add_scope()`: add already-loaded objects to the current image's lookup scope.
- `pre_handler()` / `post_handler()`: intercept relocation requests before or after writes.
- `share_find_with_lazy()`: let PLT lazy binding reuse the initial relocation symbol lookup rules.
- `lazy_pre_find_fn()` / `lazy_post_find_fn()`: configure separate lookup rules for lazy fixups.

Lazy-binding APIs require the `lazy-binding` feature.

### Use Linker to Manage Runtime Dependency Graphs

Use `Linker` when loading is more than "open this one file." It resolves root modules and `DT_NEEDED` dependencies through `KeyResolver`, then commits loaded modules into a caller-provided `LinkContext` so different loading domains can keep isolated dependency graphs and symbol scopes.

| Component | Role |
| --- | --- |
| `KeyResolver` | Resolves root keys and `DT_NEEDED` names into concrete ELF inputs |
| `LinkContext` | Stores an isolated set of loaded modules, dependencies, and symbol scopes; separate contexts do not share state automatically |
| `LinkPipeline` | Runs passes before mapping in `load_scan_first()` to adjust layout, materialization, or section data |
| `map_relocator()` | Configures host symbols, scopes, lazy binding, or relocation handlers before final relocation |

`Linker` exposes two loading interfaces:

| API | Behavior |
| --- | --- |
| `Linker::load()` | Resolves dependencies and relocates during loading; use it when you need dependency graphs, scopes, and context isolation |
| `Linker::load_scan_first()` | Scans the whole pending group and builds a mutable link plan first; use it for pre-map layout planning and dynamic link-time optimization |

The minimal shape is: implement a resolver, then pass a root key to `load()`:

```rust
use elf_loader::{input::ElfFile, Result};
use elf_loader::linker::{
    DependencyRequest, KeyResolver, LinkContext, Linker, ResolvedKey,
};

struct Resolver;

impl KeyResolver<'static, &'static str, ()> for Resolver {
    fn load_root(&mut self, key: &&'static str) -> Result<ResolvedKey<'static, &'static str>> {
        Ok(ResolvedKey::load(*key, ElfFile::from_path("path/to/plugin.so")?))
    }

    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, &'static str>,
    ) -> Result<ResolvedKey<'static, &'static str>> {
        let resolved = match req.needed() {
            "libdep.so" => ResolvedKey::load("dep", ElfFile::from_path("path/to/libdep.so")?),
            _ => return Err(req.unresolved()),
        };
        Ok(resolved)
    }
}

fn main() -> Result<()> {
    let mut context = LinkContext::<&'static str, ()>::new();

    let plugin = Linker::new()
        .resolver(Resolver)
        .load(&mut context, "plugin")?;

    let run = unsafe {
        plugin
            .get::<extern "C" fn() -> i32>("run")
            .expect("symbol `run` not found")
    };
    let _ = run();

    Ok(())
}
```

For layout optimization, switch to `load_scan_first()` and add passes with `map_pipeline()`. Configure host symbols or relocation interception with `map_relocator()`.

### Dynamic Link-Time Optimization and Huge-Page Layout

If you want to reorder sections at runtime, the target ELF must retain relocation information. A common approach is to pass `--emit-relocs` to the linker when building the target dynamic library or executable, for example through `-Wl,--emit-relocs`.

Scan-first passes can inspect sections, modify data, adjust materialization, and place code, read-only data, writable data, or TLS into different arenas. For performance-sensitive server applications, common strategies include:

| Optimization | What a pass can do |
| --- | --- |
| Hot-code packing | Place hot code sections into a tighter executable arena to reduce locality loss |
| Huge-page mapping | Choose `Huge2MiB` / `Huge1GiB` page sizes for code or read-only data arenas |
| Custom layout | Rearrange section placement by profile data, module source, symbol grouping, or application policy |
| Relocation-time rewriting | Use retained relocation information to repair metadata affected by layout changes before final relocation |

See `cargo run --example load_scan_first` for a complete scan-first loading flow. If you want to write your own layout optimization pass, start with `LinkPipeline`, `ReorderPass`, `ArenaDescriptor`, and `Section`.

### Mix `.o` and `.so`

With the `object` feature enabled, you can load a relocatable object first and use it as a lookup scope for later dynamic libraries:

```rust
use elf_loader::{Loader, Result};

fn main() -> Result<()> {
    let mut loader = Loader::new();

    let base = loader
        .load_object("path/to/base.o")?
        .relocator()
        .pre_find_fn(|_| None)
        .relocate()?;

    let plugin = loader
        .load_dylib("path/to/plugin.so")?
        .relocator()
        .scope([&base])
        .relocate()?;

    let _ = plugin;
    Ok(())
}
```

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
| `from_memory` | Load ELF data from a byte buffer | `cargo run --example from_memory` |
| `load_exec` | Inspect executable entry and base addresses | `cargo run --example load_exec` |
| `load_hook` | Observe segment loading with `with_hook()` | `cargo run --example load_hook` |
| `load_scan_first` | Discover `DT_NEEDED`, run scan-first passes, and configure pre-map layout | `cargo run --example load_scan_first` |
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

- Symbol lookup is name-based and does not perform Rust name mangling for you. Export C ABI symbols when you want stable runtime lookup names.

## Contributing

Issues and pull requests are welcome, especially around platform support and documentation examples.

- Open an issue if you hit a loader or relocation edge case.
- Send a PR if you want to improve architecture support, examples, or diagnostics.
- Star the project if it is useful in your work.

## License

This project is dual-licensed under either of the following:

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

## Contributors

<a href="https://github.com/weizhiao/elf_loader/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=weizhiao/elf_loader" alt="Project contributors">
</a>
