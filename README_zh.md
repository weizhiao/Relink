# Relink：Rust 的运行时 ELF 加载与链接

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
  <strong>在运行时完成 ELF 的映射、重定位与链接。</strong><br>
  从文件路径和内存字节流，到共享对象、可执行文件和可重定位目标文件。
</p>

<p align="center">
  <code>ET_DYN</code> · <code>ET_EXEC</code> · <code>ET_REL</code> · <code>no_std</code> · <code>类型化符号</code> · <code>混合链接</code>
</p>

Relink 是一个高性能、`no_std` 友好的 Rust ELF 加载器与运行时链接器。它适合插件系统、JIT、运行时、内核、嵌入式加载器、热更新工作流，以及任何觉得 `dlopen` 过于僵硬、但又不想长期维护手写重定位逻辑的场景。

## 可以加载什么

- 共享对象 / 动态库（`ET_DYN`）
- 可执行文件与 PIE 风格镜像（`ET_EXEC`，以及按可执行文件处理的 `ET_DYN`）
- 开启 `object` feature 后的可重定位目标文件（`ET_REL`）
- 来自文件或内存的输入：`&str`、`String`、`&[u8]`、`&Vec<u8]`、`ElfFile`、`ElfBinary`

如果你希望自动识别 ELF 类型，可以用 `Loader::load()`。如果你希望做严格类型校验，可以分别使用 `load_dylib()`、`load_exec()` 和 `load_object()`。

## 为什么用 Relink

| 如果你需要... | Relink 提供... |
| --- | --- |
| 从文件或内存进行运行时加载 | `Loader::load*` 可接受路径、`ElfFile`、`ElfBinary`、`&[u8]` 和 `&Vec<u8]` |
| 更安全的符号访问 | 与已加载镜像生命周期绑定的类型化 `get::<T>()` |
| 宿主主导的链接策略 | `pre_find_fn()`、`post_find_fn()`、`pre_handler()`、`post_handler()` |
| 运行时混合链接 | 通过 `scope()` 和 `add_scope()` 组合 `.so` 与 `.o` |
| 更底层的部署环境 | `no_std` 核心设计和可替换的 `Mmap` 后端 |

### 和常见方案相比

| 能力 | Relink | `dlopen` 风格加载 | 手写 ELF loader |
| --- | --- | --- | --- |
| 直接从内存加载 | 支持 | 往往不方便或不可用 | 支持，但要自己实现 |
| 加载可重定位对象（`ET_REL`） | 支持，feature-gated | 不支持 | 支持，但要自己实现 |
| 类型化符号生命周期安全 | 支持 | 不支持 | 取决于你的设计 |
| 自定义重定位拦截 | 支持 | 通常不支持 | 支持，但要自己实现 |
| `no_std` 友好核心 | 支持 | 不支持 | 取决于你的实现 |

## 由类型系统提供的安全性

类型化符号会借用加载出的镜像，所以它们不能活得比对应库更久。

```rust
let symbol = unsafe {
    lib.get::<fn()>("plugin_fn")
        .expect("symbol `plugin_fn` not found")
};
drop(lib);
// symbol(); // 无法编译：符号不能活得比库更久
```

## 快速开始

默认 feature 集合：

```toml
[dependencies]
elf_loader = "0.14"
```

如果你希望直接打开常见高级能力，可以启用 `full`：

```toml
[dependencies]
elf_loader = { version = "0.14", features = ["full"] }
```

### 加载动态库并调用符号

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

## 心智模型

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
   pre_find / scope / handlers / binding
                 |
    +------------+-------------+
    |            |             |
 LoadedDylib   LoadedExec   LoadedObject*
                 |
      get() / deps() / TLS / metadata

* 需要 `object` feature
```

## 常见工作流

### 从内存加载

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

如果你不在意名字显示为 `"<memory>"`，也可以直接使用 `load_dylib(&bytes)` 或 `load_exec(&bytes)`。

### 混合 `.o` 和 `.so`

这部分需要开启 `object` feature。

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

### 检查可执行文件或 PIE

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

## 最适合的场景

- 需要宿主注入符号或自定义符号搜索顺序的插件与扩展系统
- 希望从内存而不是磁盘加载 ELF 内容的 JIT 和运行时
- 需要比系统原生 loader 更高控制力的内核、嵌入式环境和底层运行时
- 受益于重定位 hook 和生命周期控制的热更新或注入式工作流
- 需要观察重定位行为的 ELF 工具链和研究型项目

## 什么时候它可能有点重

- 只是需要普通系统动态加载，且不需要自定义符号策略的应用
- 想做模块化边界，但并不希望接触 ELF 细节的项目
- 在非 `x86_64` 目标上大量依赖 `ET_REL`，且尚未在你的环境中验证支持情况的工作流

## Feature 开关

| Feature | 默认 | 作用 |
| --- | --- | --- |
| `tls` | 是 | 启用 TLS 重定位处理，以及 `Loader::with_default_tls_resolver()` 等 API |
| `lazy-binding` | 否 | 启用 PLT/GOT lazy binding，以及 `Relocator::lazy()` / `lazy_scope()` |
| `object` | 否 | 启用可重定位目标文件（`ET_REL`）加载和 `Loader::load_object()` |
| `version` | 否 | 启用带符号版本的查找，例如 `get_version()` |
| `log` | 否 | 启用基于 `log` 的加载与重定位诊断输出 |
| `portable-atomic` | 否 | 为不支持原生指针宽度原子操作的目标提供支持 |
| `use-syscall` | 否 | 在适用场景下使用 Linux syscall 后端而非 libc |
| `full` | 否 | 便捷组合：`tls`、`lazy-binding`、`object` |

说明：

- 仅仅编译进 `tls` 还不够。如果目标 ELF 实际使用 TLS 重定位，加载时需要从 `Loader::new().with_default_tls_resolver()` 开始，或者提供你自己的 TLS resolver。
- `load_object()` 是 feature-gated 的。默认 feature 下直接运行 `cargo run --example load_object` 会失败，需要加上 `--features object`。

## 示例

[`examples/`](examples/) 目录覆盖了主要扩展点：

| 示例 | 展示内容 | 运行方式 |
| --- | --- | --- |
| `load_dylib` | 加载共享对象并解析宿主符号 | `cargo run --example load_dylib` |
| `from_memory` | 从字节缓冲区加载 ELF | `cargo run --example from_memory` |
| `load_exec` | 查看可执行文件的入口地址和基址 | `cargo run --example load_exec` |
| `load_hook` | 用 `with_hook()` 观察段加载 | `cargo run --example load_hook` |
| `lifecycle` | 自定义 `.init` / `.fini` 调用流程 | `cargo run --example lifecycle` |
| `user_data` | 用 `with_context_loader()` 绑定模块级上下文 | `cargo run --example user_data` |
| `relocation_handler` | 用自定义 handler 拦截重定位 | `cargo run --example relocation_handler` |
| `load_object` | 加载可重定位目标文件 | `cargo run --example load_object --features object` |

## 平台说明

- 当前 crate 的目标架构包括 `x86_64`、`x86`、`aarch64`、`arm`、`riscv64`、`riscv32` 和 `loongarch64`。
- 动态库与可执行文件加载是这些架构上的主要支持路径。
- `.o` / `ET_REL` 支持目前主要围绕 `x86_64` 的重定位实现展开。对于非 `x86_64` 目标，请先视作实验性能力，除非你已经在自己的目标上完成验证。
- 符号查找按导出名精确匹配，不会替你做 Rust 名字改编。需要稳定运行时符号名时，建议导出 C ABI 符号。

## 参与贡献

欢迎通过 Issue 和 PR 一起把 Relink 做得更扎实，尤其欢迎补充重定位覆盖、平台支持和文档示例。

- 遇到加载器或重定位边界问题时，欢迎提 Issue。
- 想改进架构支持、示例或诊断信息时，欢迎直接发 PR。
- 如果项目对你有帮助，也欢迎点个 Star。

## 许可证

本项目采用双许可证：

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

## 贡献者

<a href="https://github.com/weizhiao/elf_loader/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=weizhiao/elf_loader" alt="Project contributors">
</a>
