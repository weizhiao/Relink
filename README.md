# Relink: Runtime ELF Loading for Rust

<p align="center">
  <img src="https://raw.githubusercontent.com/weizhiao/elf_loader/main/docs/imgs/logo.png" width="500" alt="Relink logo">
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
  <strong>Map, relocate, and link ELF images at runtime.</strong><br>
  From file paths and in-memory buffers to shared objects, executables, and relocatable objects.
</p>

<p align="center">
  <code>ET_DYN</code> · <code>ET_EXEC</code> · <code>ET_REL</code> · <code>no_std</code> · <code>Typed symbols</code> · <code>Hybrid linking</code>
</p>

Relink is a high-performance, `no_std`-friendly ELF loader and runtime linker for Rust. It is built for plugin systems, JITs, runtimes, kernels, embedded loaders, hot-reload workflows, and other environments where `dlopen`-style loading is too rigid and hand-rolled relocation logic is too painful to maintain.

## What It Loads

- Shared objects / dynamic libraries (`ET_DYN`)
- Executables and PIE-style images (`ET_EXEC`, plus executable-style `ET_DYN`)
- Relocatable object files (`ET_REL`) when the `object` feature is enabled
- File-backed or in-memory inputs via `&str`, `String`, `&[u8]`, `&Vec<u8]`, `ElfFile`, and `ElfBinary`

If you want automatic detection, use `Loader::load()`. If you want strict type checks, use `load_dylib()`, `load_exec()`, or `load_object()`.

## Why Relink

| If you need... | Relink gives you... |
| --- | --- |
| Runtime loading from files or memory | `Loader::load*` accepts paths, `ElfFile`, `ElfBinary`, `&[u8]`, and `&Vec<u8]` |
| Safer symbol handling | Typed `get::<T>()` lookups tied to the loaded image lifetime |
| Host-controlled linking | `pre_find_fn()`, `post_find_fn()`, `lazy_pre_find_fn()`, `lazy_post_find_fn()`, `pre_handler()`, and `post_handler()` |
| Hybrid linking at runtime | Mix `.so` and `.o` inputs with `scope()` and `add_scope()` |
| Low-level deployment targets | A `no_std` core plus custom `Mmap` backends |

### Compared With Typical Approaches

| Capability | Relink | `dlopen`-style loading | Hand-rolled ELF loader |
| --- | --- | --- | --- |
| Load directly from memory | Yes | Usually awkward or unavailable | Yes, if you build it |
| Load relocatable objects (`ET_REL`) | Yes, feature-gated | No | Yes, if you build it |
| Typed symbol lifetime safety | Yes | No | Depends on your design |
| Custom relocation interception | Yes | Usually no | Yes, if you build it |
| `no_std`-friendly core | Yes | No | Depends on your implementation |

## Safety by Construction

Typed symbols borrow the loaded image, so they cannot outlive the library that produced them.

```rust
let symbol = unsafe {
    lib.get::<fn()>("plugin_fn")
        .expect("symbol `plugin_fn` not found")
};
drop(lib);
// symbol(); // does not compile: the symbol cannot outlive the library
```

## Quick Start

Add the crate with the default feature set:

```toml
[dependencies]
elf_loader = "0.14"
```

Or enable the common advanced feature bundle:

```toml
[dependencies]
elf_loader = { version = "0.14", features = ["full"] }
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

## Mental Model

```text
path / bytes / ElfFile / ElfBinary
                 |
               Loader
                 |
    +------------+-------------+
    |            |             |
 RawDylib      RawExec     RawObject*
                 |
              Relocator
   pre_find / scope / lazy lookups / handlers / binding
                 |
    +------------+-------------+
    |            |             |
 LoadedDylib   LoadedExec   LoadedObject*
                 |
      get() / deps() / TLS / metadata

* requires the `object` feature
```

## Common Workflows

### Load from Memory

```rust
use elf_loader::{Loader, Result, input::ElfBinary};

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

`load_dylib(&bytes)` and `load_exec(&bytes)` also work if a synthetic name such as `"<memory>"` is acceptable.

### Mix `.o` and `.so` Inputs

This requires the `object` feature.

```rust,no_run
# use elf_loader::{Loader, Result};
# fn main() -> Result<()> {
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
# let _ = plugin;
# Ok(())
# }
```

### Configure Lazy Binding Fixups

This requires the `lazy-binding` feature.

```rust,no_run
# use elf_loader::{Loader, Result};
# extern "C" fn host_double(value: i32) -> i32 { value * 2 }
# fn main() -> Result<()> {
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
    .share_find_with_lazy()
    .lazy()
    .relocate()?;
# let _ = lib;
# Ok(())
# }
```

Use `share_find_with_lazy()` when PLT fixups should reuse the same host lookup policy as the initial relocation pass. If lazy fixups need different rules, configure `lazy_pre_find_fn()` / `lazy_post_find_fn()` directly.

### Inspect an Executable or PIE

```rust
use elf_loader::{Loader, Result};

fn main() -> Result<()> {
    let mut loader = Loader::new();
    let exec = loader.load_exec("path/to/program")?;

    println!("name  = {}", exec.name());
    println!("entry = 0x{:x}", exec.entry());
    println!("base  = 0x{:x}", exec.base());

    Ok(())
}
```

## Where It Fits Best

- Plugin and extension systems that need host-provided symbols or custom symbol search order
- JITs and runtimes that want to load ELF content from memory instead of only from disk
- Kernels, embedded environments, and low-level runtimes that need more control than an OS-native loader exposes
- Hot-reload or instrumentation workflows that benefit from relocation hooks and lifecycle control
- ELF-focused tooling and research projects where visibility into relocation behavior matters

## Where It May Be Too Much

- Applications that only need plain OS-native dynamic loading with no custom symbol policy
- Projects that want a module/plugin boundary but do not want to think about ELF details at all
- Heavy `ET_REL` workflows on non-`x86_64` targets that have not been validated in your environment yet

## Feature Flags

| Feature | Default | Purpose |
| --- | --- | --- |
| `tls` | Yes | Enables TLS relocation handling and APIs such as `Loader::with_default_tls_resolver()` |
| `lazy-binding` | No | Enables PLT/GOT lazy binding plus `Relocator::lazy()`, `share_find_with_lazy()`, and `lazy_pre_find*()` / `lazy_post_find*()` |
| `object` | No | Enables relocatable object (`ET_REL`) loading via `Loader::load_object()` |
| `version` | No | Enables version-aware symbol lookup such as `get_version()` |
| `log` | No | Enables `log` integration for loader and relocation diagnostics |
| `portable-atomic` | No | Adds support for targets without native pointer-sized atomics |
| `use-syscall` | No | Uses the Linux syscall backend instead of libc where applicable |
| `full` | No | Convenience bundle for `tls`, `lazy-binding`, and `object` |

Notes:

- Compiling with `tls` is not enough by itself for TLS-using modules. Start from `Loader::new().with_default_tls_resolver()` or provide your own TLS resolver when loading ELF objects that require TLS relocations.
- `load_object()` is feature-gated. `cargo run --example load_object` will fail under the default feature set unless you add `--features object`.

## Examples

The [`examples/`](examples/) directory covers the main extension points:

| Example | What it demonstrates | Command |
| --- | --- | --- |
| `load_dylib` | Load shared objects and resolve host symbols | `cargo run --example load_dylib` |
| `from_memory` | Load ELF data from a byte buffer | `cargo run --example from_memory` |
| `load_exec` | Inspect executable metadata such as entry/base | `cargo run --example load_exec` |
| `load_hook` | Observe segment loading with `with_hook()` | `cargo run --example load_hook` |
| `lifecycle` | Custom `.init` / `.fini` handling | `cargo run --example lifecycle` |
| `user_data` | Attach per-image metadata with `with_context_loader()` | `cargo run --example user_data` |
| `relocation_handler` | Intercept relocations with a custom handler | `cargo run --example relocation_handler` |
| `load_object` | Load relocatable object files | `cargo run --example load_object --features object` |

## Platform Notes

- The crate currently targets `x86_64`, `x86`, `aarch64`, `arm`, `riscv64`, `riscv32`, and `loongarch64`.
- Dynamic library and executable loading are the primary supported paths across those architectures.
- Relocatable object (`.o`) support is currently centered on `x86_64` relocation handling. Treat non-`x86_64` object loading as experimental unless you have validated it for your own target.
- Symbol lookup is name-based and does not perform Rust name mangling for you. Export C ABI symbols when you want stable runtime lookup names.

## Contributing

Issues and pull requests are welcome, especially around relocation coverage, platform support, and documentation.

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
