# windows-elf-loader

Load ELF shared libraries on Windows using [Relink](https://github.com/weizhiao/Relink).
`WinElfLoader::load_file` reads a library from disk; `load_dylib` accepts a named
byte buffer. Both return an unrelocated `RawDylib` for use with `Relocator`.

## Example

On x86-64 Windows, run the bundled example from the repository root:

```sh
cargo run -p windows-elf-loader --release --example load
```

The [example](examples/load.rs) supplies a host `print` function through a
`SyntheticModule`, relocates `liba.so`, and calls its exported `a` function.
Both the callback and the exported function use `extern "sysv64"` to match the
ELF library's calling convention.

## Requirements

- Supply the library's dependencies and imported symbols explicitly.
- ELF code must use the host's instruction set and the correct ABI at every
  call boundary. Linux system calls cannot be used directly on Windows.
- The default TLS resolver does not support registrations on Windows, including
  static TLS and custom providers. Libraries requiring TLS need a custom
  `TlsResolver`, configured through Relink's `Loader` and `Domain` APIs.
