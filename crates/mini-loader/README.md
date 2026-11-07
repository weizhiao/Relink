[![](https://img.shields.io/crates/v/mini-loader.svg)](https://crates.io/crates/mini-loader)
[![](https://img.shields.io/crates/d/mini-loader.svg)](https://crates.io/crates/mini-loader)
[![license](https://img.shields.io/crates/l/mini-loader.svg)](https://crates.io/crates/mini-loader)
[![Rust](https://img.shields.io/badge/rust-1.93.0%2B-blue.svg?maxAge=3600)](https://github.com/weizhiao/Relink)

# mini-loader

`mini-loader` loads and executes Linux ELF executables (`ET_EXEC`) and
position-independent executables (`ET_DYN`). It supports `x86_64`, `riscv64`,
and `aarch64`. The target must match the machine that will run the loader.

## Installation
### x86_64
```shell
cargo install mini-loader --target x86_64-unknown-none
```
### aarch64
```shell
RUSTFLAGS="-C relocation-model=pic -C link-arg=-pie" cargo install mini-loader --target aarch64-unknown-none
```
### riscv64
```shell
RUSTFLAGS="-C relocation-model=pic -C link-arg=-pie" cargo install mini-loader --target riscv64gc-unknown-none-elf
```

## Usage
Load and execute `ls`:

```shell
mini-loader /bin/ls
```
