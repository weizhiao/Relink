# Relink：Rust ELF 加载器与运行时链接器

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
  <strong>高性能 · 可定制 · 支持 no_std</strong>
</p>

Relink 是用 Rust 编写的 ELF 加载器与运行时链接器，面向插件、JIT 和自定义运行时。你可以自主控制依赖解析、符号绑定、内存布局与加载生命周期。

[快速开始](#快速开始) · [性能数据](#基准测试) · [平台支持](#平台支持) · [运行示例](examples/README.md) · [API 文档](https://docs.rs/elf_loader)

## 核心能力

- **多种输入**：从文件或内存加载共享库、可执行文件与可重定位目标文件（`.o` / `.ko`）。
- **链接策略可控**：自定义依赖解析、符号作用域和重定位，通过 observer 跟踪或干预加载过程。
- **加载前优化**：先扫描再布局，支持 section 重排与热代码聚集；架构范围见[平台支持](#平台支持)。
- **适配你的运行时**：支持 `no_std`，可替换 mmap 与内存访问后端，接入内核、嵌入式或远程内存。

## 基准测试

在本次 10 个系统库与 `libloading` 0.9.0（glibc）的对照中，Relink **加载耗时减少约 4–32%**，**符号命中耗时约为 1/3**。
图中为平均耗时和 95% 置信区间，越低越好。

**加载与卸载 · µs**

![Relink 与 libloading 的加载和卸载耗时对比](benches/figures/load-teardown-dark.svg#gh-dark-mode-only)
![Relink 与 libloading 的加载和卸载耗时对比](benches/figures/load-teardown.svg#gh-light-mode-only)

卸载耗时整体相近。不计入 context 创建、销毁及宿主导入。

**符号查找 · ns**

![Relink 与 libloading 的符号命中和未命中耗时对比](benches/figures/symbol-lookup-dark.svg#gh-dark-mode-only)
![Relink 与 libloading 的符号命中和未命中耗时对比](benches/figures/symbol-lookup.svg#gh-light-mode-only)

符号查找比较的是公开 API：Relink 搜索根库导出，`dlsym` 还可能搜索依赖；未命中包含各自的错误处理成本。

| 测试配置 | 值 |
| --- | --- |
| 日期 / commit | 2026-10-29 · `ed37e60` |
| 环境 | Ryzen 9 7945HX · Linux 7.0.11-arch1-1 x86_64 · glibc 2.43 · Rust 1.96.0 |
| 采样 | 固定 CPU 2；每项预热 1 秒、测量 2 秒、30 个样本；热文件缓存 |

复现：`taskset -c 2 bash ci/bench.sh`。依赖与测量口径见[基准指南](benches/README.md)。

## 快速开始

```toml
[dependencies]
elf_loader = "0.18.0"
```

下面的例子加载动态库、调用函数并释放模块。先按[示例指南](examples/README.md#build-the-example-library)
编译 `libexample.so`，从仓库根目录运行；也可直接执行 `cargo run --example linker_load`。

```rust
use elf_loader::{LinkContext, Linker, input::PathBuf, linker::SearchPathResolver};
use std::ffi::c_int;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut context = LinkContext::for_process();
    let loaded = Linker::new()
        .with_resolver(SearchPathResolver::new())
        .run()
        .load(&mut context, PathBuf::from("target/example-library/libexample.so"))?;

    // SAFETY: example.c 定义了 int example_add(int, int)。
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

更多用法：[内存加载](examples/load_from_memory.rs) · [目标文件](examples/load_object.rs) · [布局重排](examples/linker_scan_first.rs) · [宿主库导入](examples/host_import.rs)。

## 平台支持

| 指令集 | 动态库 / 可执行文件 | Section 重排 | `.o` / `ET_REL` |
| --- | --- | --- | --- |
| `x86_64` | ✅ | ✅ | ✅ |
| `x86` | ✅ | 🚧 | 🚧 |
| `aarch64` | ✅ | 🚧 | 🚧 |
| `arm` | ✅ | 🚧 | 🚧 |
| `riscv64` | ✅ | 🚧 | ✅ |
| `riscv32` | ✅ | 🚧 | 🚧 |
| `loongarch64` | ✅ | 🚧 | 🚧 |
| `xtensa` | 🔧 | 🚧 | 🚧 |

✅ 支持 · 🔧 部分支持 · 🚧 待补齐。

Xtensa 目前支持动态重定位，但尚不支持 lazy binding 和 TLS 相关重定位。

## Feature 开关

默认 `full` 启用 `libc`、`object` 和 `lazy-binding`。最小 libc 配置：

```toml
elf_loader = { version = "0.18.0", default-features = false, features = ["libc"] }
```

<details>
<summary>查看全部 feature</summary>

| Feature | 默认 | 作用 |
| --- | --- | --- |
| `libc` | 是 | 在 Linux/Android 上使用 libc 后端；在 Linux/glibc 上提供 `host::open` |
| `lazy-binding` | 是 | 启用内置的本机 PLT/GOT lazy binder |
| `object` | 是 | 启用可重定位目标文件（`ET_REL`）加载和 `LoaderRun::load_object()` |
| `version` | 否 | 启用带符号版本的查找，例如 `get_version()` |
| `log` | 否 | 启用基于 `log` 的加载与重定位诊断输出 |
| `portable-atomic` | 否 | 为不支持原生指针宽度原子操作的目标提供支持 |
| `use-syscall` | 否 | 在 Linux 上使用 syscall 后端，而不是 libc |
| `full` | 是 | 便捷组合：`lazy-binding`、`object`、`libc` |

</details>

TLS 通过 resolver 配置，无需 feature 开关；宿主库需要显式导入，见[示例](examples/host_import.rs)。

## 参与贡献

提交 [Issue](https://github.com/weizhiao/Relink/issues) 反馈问题，或按[贡献指南](CONTRIBUTING_zh.md) 提交改进。

## 许可证

采用 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 双许可证。

## 贡献者

<a href="https://github.com/weizhiao/Relink/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=weizhiao/Relink" alt="Project contributors">
</a>
