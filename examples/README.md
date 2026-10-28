# Examples

Run commands from the repository root.

## Build the example library

The basic examples share [`library/example.c`](library/example.c), which has no
external runtime dependencies. Use an ELF C compiler matching the Rust runner's
architecture and calling convention:

```sh
mkdir -p target/example-library
cc -c -fPIC -fno-stack-protector -fno-asynchronous-unwind-tables \
  examples/library/example.c -o target/example-library/example.o
cc -shared -nostdlib -Wl,--emit-relocs target/example-library/example.o \
  -o target/example-library/libexample.so
```

## Run

The six basic examples use fixed paths under `target/example-library`:

```sh
cargo run --example load_dylib
cargo run --example load_from_memory
cargo run --example load_object
cargo run --example linker_load
cargo run --example linker_scan_first
cargo run --example observer
```

`load_object` requires `object` (enabled by default). `linker_scan_first` requires
x86-64 and the retained relocations produced above; do not strip the library.
Function calls print `example_add(2, 3) = 5` or `example_value() = 7`.

## Host imports

`host_import` loads system zlib through Relink using host libc. It requires
Linux/glibc, `libc` (enabled by default), `version`, `libz.so.1`, and
`/etc/ld.so.cache`:

```sh
cargo run --example host_import --features version
```

## Other examples

- `cargo run --example load_exec -- /path/to/program`: map an ELF executable and
  inspect its entry point without executing it.
- `load_bench`: see [`benches/README.md`](../benches/README.md) for timing commands.
- [`xtensa-qemu`](xtensa-qemu): standalone cross-target example and setup.
