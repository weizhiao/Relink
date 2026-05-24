# Relink：Rust ELF 加载器与 Runtime/JIT 链接器

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
  <strong>在 Rust / no_std 环境中加载、链接和改写 ELF。</strong>
</p>

Relink 是一个 Rust ELF 加载与运行时链接库。它可以从文件或内存加载 `.so`、可执行文件和目标文件，并完成依赖解析、重定位和符号查找。

当 `dlopen` 的行为不够可控时，Relink 可以让你自己决定怎么找依赖、怎么查符号、怎么映射内存，以及是否在加载前先扫描和调整布局。

## 什么时候用

- 运行时加载插件、JIT 产物或热更新模块。
- 需要自己控制 `DT_NEEDED` 依赖、符号作用域或重定位处理。
- 需要从内存加载 ELF，或接入自己的 mmap / 内存管理后端。
- 需要先扫描依赖和 section，再做布局重排、热路径代码聚集、大页映射或自定义处理。
- 需要在 `no_std`、内核、嵌入式或非标准运行时中保留 ELF 加载能力。

## 可以加载什么

- 共享对象 / 动态库（`ET_DYN`）
- 可执行文件与 PIE 风格镜像（`ET_EXEC`，以及按可执行文件处理的 `ET_DYN`）
- 开启 `object` feature 后的可重定位目标文件（`ET_REL`）
- 来自文件或内存的输入：`&str`、`String`、`&[u8]`、`Vec<u8>`、`ElfFile`、`ElfBinary`

自动识别 ELF 类型时使用 `Loader::load()`；需要严格类型校验时使用 `load_dylib()`、`load_exec()` 或 `load_object()`。

## 核心能力

| 能力 | Relink 提供什么 |
| --- | --- |
| 内存加载 | 可从路径、内存缓冲区或已解析输入加载 ELF |
| 可定制链接策略 | 自己决定依赖怎么解析、符号在哪找、重定位如何拦截 |
| 链接上下文隔离 | 多个 `LinkContext` 拥有独立的已加载模块集合、依赖图和符号作用域 |
| Scan-first 规划 | 先看清依赖和 section，再决定怎么映射、重排或改写 |
| 加载前布局优化 | 配合 `--emit-relocs` 做 section 重排、热路径代码聚集或自定义处理 |
| 可替换映射后端 | 可以接入自己的 mmap、页大小、权限和内存访问模型 |
| 类型安全符号访问 | 符号生命周期绑定到已加载镜像，减少悬垂符号风险 |
| 混合加载 | 同一流程中组合 `.so`、可执行镜像和 `.o` / `ET_REL` |

### 和 `dlopen` 相比

| 能力 | Relink | `dlopen` 风格加载 |
| --- | --- | --- |
| 内存加载 | ✅ 路径 / 内存缓冲区 / 已解析 ELF | ❌ |
| `ET_REL` 加载 | ✅ 需开启 feature | ❌ |
| 链接前规划 | ✅ 可先扫描依赖和 section | ❌ |
| 加载前布局优化 | ✅ section 重排 / 热路径代码聚集 / 自定义处理 | ❌ |
| 映射策略 | ✅ mmap 后端、页大小和权限策略可替换 | ❌ |
| 依赖与符号策略 | ✅ 依赖图 / 作用域 / 查找 / 拦截可控 | ❌ |
| 上下文隔离 | ✅ 多个 `LinkContext` 隔离依赖图和符号作用域 | ❌ |
| 异构加载 | ✅ 可扫描和装载不同 ELF / ABI / 目标架构镜像 | ❌ |

## 快速开始

默认 feature 集合适合直接加载动态库、可执行文件和处理 TLS：

```toml
[dependencies]
elf_loader = "0.15.1"
```

如果你希望一次打开常见高级能力，可以启用 `full`：

```toml
[dependencies]
elf_loader = { version = "0.15.1", features = ["full"] }
```

### 加载动态库并调用符号

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

## 加载路径

| 路径 | 入口 | 适合 |
| --- | --- | --- |
| 直接加载 | `Loader::load_dylib()` / `load_exec()` / `load_object()` | 已经知道要加载哪个 ELF |
| 自动解析依赖 | `Linker::load()` | 需要处理 `DT_NEEDED`、依赖图和符号作用域 |
| 先扫描再加载 | `Linker::load_scan_first()` | 需要在映射前查看依赖和 section，并运行布局 pass |
| 加载 `.o` | `Loader::load_object()` | 需要组合 `.o` 与 `.so`；需开启 `object` feature |
| 自定义内存环境 | `Loader::with_mmap(mapper)` / `with_page_size()` | 需要接入自己的 mmap 后端、页大小或权限策略 |

## 进阶能力索引

| 主题 | 入口 / 示例 |
| --- | --- |
| 从内存加载 | `ElfBinary::new(name, bytes)`，或直接 `load_dylib(&bytes)` / `load_exec(&bytes)` |
| 宿主符号与 scope | `SyntheticModule`、`scope()`、`extend_scope()` |
| 重定位拦截 | `pre_handler()`、`post_handler()`，见 `cargo run --example relocation_handler` |
| Lazy binding | `relocator().lazy()`，需要 `lazy-binding` feature |
| 运行时依赖图 | `KeyResolver`、`LinkContext`、`Linker::load()` |
| 映射前布局优化 | `Linker::load_scan_first()`、`map_pipeline()`，见 `cargo run --example linker_scan_first` |
| 可重定位对象 | `cargo run --example load_object --features object` |
| 生命周期回调 | `cargo run --example lifecycle` |

如果你要做 section 重排、热路径代码聚集这类加载前优化，目标 ELF 通常需要在链接阶段保留重定位信息，例如传给链接器 `-Wl,--emit-relocs`。

## 基准测试

下表是 GitHub Actions 上的一次性能快照，只适合作为当前测试集的参考。完整环境见 [actions/runs/25632675040/job/75239090388](https://github.com/weizhiao/Relink/actions/runs/25632675040/job/75239090388)。fixture 是仓库内的 `libc -> libb -> liba` 测试链，不是系统 C library。

加载耗时越低越好。`scan_first` 包含依赖扫描和 section 规划成本，因此不是和 `dlopen` 完全同质的直接替换。

| 测试项 | 耗时 | 相对耗时 |
| --- | ---: | --- |
| `elf_loader/memory` | `89.531 µs` | `0.78x` |
| `elf_loader/file` | `101.01 µs` | `0.88x` |
| `linker/runtime` | `111.32 µs` | `0.97x` |
| `libloading/lazy` | `115.34 µs` | `1.00x` |
| `libloading/now` | `115.77 µs` | `1.00x` |
| `linker/scan_first` | `288.92 µs` | `2.51x` |

符号查找对比是在两边都已经加载完 fixture chain 后测量的：

| 测试项 | 耗时 | 相对耗时 |
| --- | ---: | --- |
| `symbol/elf_loader/hit` | `10.280 ns` | `0.13x` |
| `symbol/libloading/hit` | `80.154 ns` | `1.00x` |
| `symbol/elf_loader/miss` | `11.548 ns` | `0.03x` |
| `symbol/libloading/miss` | `375.49 ns` | `1.00x` |

## Feature 开关

| Feature | 默认 | 作用 |
| --- | --- | --- |
| `libc` | 是 | 在 Unix-like 平台使用 libc 后端 |
| `tls` | 是 | 启用 TLS 重定位处理和内置 TLS resolver |
| `lazy-binding` | 否 | 启用 PLT/GOT lazy binding 和 lazy fixup 查找配置 |
| `object` | 否 | 启用可重定位目标文件（`ET_REL`）加载和 `Loader::load_object()` |
| `version` | 否 | 启用带符号版本的查找，例如 `get_version()` |
| `log` | 否 | 启用基于 `log` 的加载与重定位诊断输出 |
| `portable-atomic` | 否 | 为不支持原生指针宽度原子操作的目标提供支持 |
| `use-syscall` | 否 | 在 Linux 上使用 syscall 后端，而不是 libc |
| `full` | 否 | 便捷组合：`tls`、`lazy-binding`、`object`、`libc` |

说明：

- 默认 feature 是 `tls` + `libc`。
- 仅仅编译进 `tls` 还不够。如果目标 ELF 实际使用 TLS 重定位，加载时需要从 `Loader::new().with_default_tls_resolver()` 开始，或者提供你自己的 TLS resolver。
- `load_object()` 是 feature-gated 的。默认 feature 下直接运行 `cargo run --example load_object` 会失败，需要加上 `--features object`。

## 示例

[`examples/`](examples/) 目录覆盖主要扩展点：

| 示例 | 展示内容 | 运行方式 |
| --- | --- | --- |
| `load_dylib` | 加载共享对象并解析宿主符号 | `cargo run --example load_dylib` |
| `linker_load` | 使用 `Linker::load()` 解析 `DT_NEEDED` 依赖 | `cargo run --example linker_load` |
| `from_memory` | 从字节缓冲区加载 ELF | `cargo run --example from_memory` |
| `load_exec` | 查看可执行文件的入口地址和基址 | `cargo run --example load_exec` |
| `load_hook` | 用 `with_hook()` 观察段加载 | `cargo run --example load_hook` |
| `linker_scan_first` | 发现 `DT_NEEDED`、运行 scan-first pass 并配置映射前布局 | `cargo run --example linker_scan_first` |
| `lifecycle` | 自定义 `.init` / `.fini` 调用流程 | `cargo run --example lifecycle` |
| `user_data` | 初始化 dynamic image 级上下文 | `cargo run --example user_data` |
| `relocation_handler` | 用自定义 handler 拦截重定位 | `cargo run --example relocation_handler` |
| `load_object` | 加载可重定位目标文件 | `cargo run --example load_object --features object` |

## 平台说明

| 指令集 | 动态库 / 可执行文件 | 加载前布局优化 | `.o` / `ET_REL` |
| --- | --- | --- | --- |
| `x86_64` | ✅ | ✅ | ✅ |
| `x86` | ✅ | 🟡 | ⏳ |
| `aarch64` | ✅ | 🟡 | ⏳ |
| `arm` | ✅ | 🟡 | ⏳ |
| `riscv64` | ✅ | 🟡 | ⏳ |
| `riscv32` | ✅ | 🟡 | ⏳ |
| `loongarch64` | ✅ | 🟡 | ⏳ |

符号：✅ 支持，🟡 基础支持，⏳ 待实现。复杂 section 重排修复和 `.o` / `ET_REL` 目前主要围绕 `x86_64` 的重定位实现展开；其他架构欢迎补齐。

符号查找按导出名精确匹配，不会替你做 Rust 名字改编。需要稳定运行时符号名时，建议导出 C ABI 符号。

## 参与贡献

欢迎通过 Issue 和 PR 一起把 Relink 做得更好。如果项目对你有帮助，也欢迎点个 Star。

## 许可证

本项目采用双许可证：

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

## 贡献者

<a href="https://github.com/weizhiao/elf_loader/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=weizhiao/elf_loader" alt="Project contributors">
</a>
