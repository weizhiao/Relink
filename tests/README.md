# End-to-end tests

On Linux with glibc, run `cargo test --locked --features version` with a C
compiler, `libz.so.1`, and `libexpat.so.1` installed. Set `CC` to select the
fixture compiler when cross-compiling.

| Test target | Public interfaces | Observable result |
| --- | --- | --- |
| [modules](modules.rs) | `KeyResolver`, `SyntheticModule`, `get_version` | Retry a plugin after a missing dependency. Its code calls a host function and reads the default version of a host variable. An explicit lookup reads the older value. |
| [modules](modules.rs) | `DsoBuilder`, `Loader::with_arch`, `AllocMmap` | Generate an i386 shared object in memory and read an exported revision string on the test host. This case also runs with `--no-default-features`. |
| [runtime](runtime.rs) | `Linker`, `SearchPathResolver`, `LinkContext::import`, `module_loader` | Import a plugin and its dependency into another context. Release the source and call the imported plugin. |
| [runtime](runtime.rs) | `DefaultTlsResolver`, object loading and relocation | Two threads modify independent counters. On x86-64 and RISC-V 64, code in one `.o` calls code in another. |
| [runtime](runtime.rs) | `LoaderRun::scan`, `load_scanned_dynamic`, `RawElf::interp` | Scanning and loading preserve the same non-UTF-8 interpreter path. |
| [extensions](extensions.rs) | `ElfBinary`, relocation observers, `defer_init`, lazy binding | Observe a constructor's result before and after initialization and bind a late host callback. |
| [real_libraries](real_libraries.rs) | Host imports, loader cache, typed symbol lookup | Relink and glibc open the same zlib and Expat files and return the expected CRC-32 and XML parse results. |

The [mini-loader](../crates/mini-loader) exercises process startup in CI. The
[Xtensa example](../examples/xtensa-qemu) calls a plugin through a custom memory
mapping in QEMU. The [benchmarks](../benches/README.md) measure huge-page policy.
