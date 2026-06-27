# Relink：Rust ELF 加载器与运行时链接器

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

## 什么时候用

- 运行时加载插件、JIT 产物或热更新模块。
- 需要自己控制 `DT_NEEDED` 依赖、符号作用域或重定位处理。
- 需要从内存加载 ELF，或接入自己的 mmap / 内存管理后端。
- 需要先扫描依赖和 section，再做布局重排、热路径代码聚集、大页映射或自定义处理。
- 需要加载 `.o` / `.ko` 这类可重定位 ELF。
- 需要在 `no_std`、内核、嵌入式或非标准运行时中保留 ELF 加载能力。

## 可以加载什么

- 共享对象 / 动态库（`ET_DYN`）
- 可执行文件与 PIE 风格镜像（`ET_EXEC`，以及按可执行文件处理的 `ET_DYN`）
- 开启 `object` feature 后的可重定位目标文件（`ET_REL`，例如 `.o` / `.ko`）

## 和 `dlopen` 相比

| 能力 | Relink | `dlopen` 风格加载 |
| --- | --- | --- |
| 内存加载 | ✅ 可从路径、字节缓冲区或已解析 ELF 输入加载 | ❌ |
| `ET_REL` 加载 | ✅ 可加载和重定位 `.o` / `.ko` / `ET_REL` 文件 | ❌ |
| 链接前规划 | ✅ 可先解析依赖和 section，再决定映射方式 | ❌ |
| 加载前布局优化 | ✅ 可在映射前调整 section 布局，用于热路径聚集或自定义重排 | ❌ |
| 映射策略 | ✅ 可替换 mmap、页大小、权限和内存访问后端 | ❌ |
| 依赖与符号策略 | ✅ 可自定义 `DT_NEEDED` 解析、符号 scope 和重定位拦截 | ❌ |
| 上下文隔离 | ✅ 多个 `LinkContext` 独立保存模块、依赖图和符号作用域 | ❌ |
| 远程 / 异构加载 | ✅ 可用自定义内存访问在本地装载远程设备或异构目标 ELF | ❌ |

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

### 使用 Linker 加载依赖

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
| `tls` | 是 | 启用内置同进程 TLS resolver |
| `lazy-binding` | 否 | 启用 PLT/GOT lazy binding 和 lazy fixup 查找配置 |
| `object` | 否 | 启用可重定位目标文件（`ET_REL`）加载和 `Loader::load_object()` |
| `version` | 否 | 启用带符号版本的查找，例如 `get_version()` |
| `log` | 否 | 启用基于 `log` 的加载与重定位诊断输出 |
| `portable-atomic` | 否 | 为不支持原生指针宽度原子操作的目标提供支持 |
| `use-syscall` | 否 | 在 Linux 上使用 syscall 后端，而不是 libc |
| `full` | 否 | 便捷组合：`tls`、`lazy-binding`、`object`、`libc` |

说明：

- 默认 feature 是 `tls` + `libc`。
- `tls` 只提供默认 resolver；使用自定义 TLS resolver 时，不需要开启这个 feature。
- `load_object()` 是 feature-gated 的。默认 feature 下直接运行 `cargo run --example load_object` 会失败，需要加上 `--features object`。

## 平台支持

| 指令集 | 动态库 / 可执行文件 | 加载前布局优化 | `.o` / `ET_REL` |
| --- | --- | --- | --- |
| `x86_64` | ✅ | ✅ | ✅ |
| `x86` | ✅ | 🟡 | ⏳ |
| `aarch64` | ✅ | 🟡 | ⏳ |
| `arm` | ✅ | 🟡 | ⏳ |
| `riscv64` | ✅ | 🟡 | ✅ |
| `riscv32` | ✅ | 🟡 | ⏳ |
| `loongarch64` | ✅ | 🟡 | ⏳ |

符号：✅ 支持，🟡 基础支持，⏳ 待实现。复杂 section 重排修复和 `.o` / `ET_REL` 目前主要围绕 `x86_64` 与 `riscv64` 的重定位实现展开；其他架构欢迎补齐。

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
