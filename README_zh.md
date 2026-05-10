# Relink：ELF 加载与动态链接时优化

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
  <strong>动态链接时优化，支持异构加载与深度定制。</strong><br>
</p>

Relink 是一个面向 Rust 运行时的 ELF 加载与链接框架，核心 `no_std` 友好。它允许调用方在动态链接阶段介入依赖解析、布局规划、映射与重定位，用于性能优化、异构加载和高度定制的加载策略。

## 适用场景

| 场景                                | Relink 适合处理的问题                                                                                                                                                                           |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 插件系统、JIT、热更新               | 运行时加载、符号解析和依赖图策略不必受限于 `dlopen` 的固定流程                                                                                                                                  |
| 高性能服务器应用                    | 在启用链接器 `--emit-relocs`、保留重定位信息后，于映射前重写 section 布局，将 hot code 聚集到更紧凑的运行时区域，并可编写自定义 pass 做更多动态链接时优化；支持大页映射以降低运行时地址转换开销 |
| 内核、嵌入式加载器、`no_std` 运行时 | 在受限环境中保留 ELF 扫描、映射和重定位能力                                                                                                                                                     |
| 异构加载                            | 在宿主环境中扫描、改写并装载不同 ELF 布局、ABI 或目标架构镜像                                                                                                                                   |
| 深度定制链接策略                    | 将依赖解析和重定位拦截组合成自己的加载流程                                                                                                                                                      |

当 `dlopen` 的固定策略不够灵活，而手写依赖解析、布局优化和重定位逻辑又成本过高时，Relink 提供可组合的替代方案。

## 可以加载什么

- 共享对象 / 动态库（`ET_DYN`）
- 可执行文件与 PIE 风格镜像（`ET_EXEC`，以及按可执行文件处理的 `ET_DYN`）
- 开启 `object` feature 后的可重定位目标文件（`ET_REL`）
- 来自文件或内存的输入：`&str`、`String`、`&[u8]`、`&Vec<u8]`、`ElfFile`、`ElfBinary`

如果你希望自动识别 ELF 类型，可以用 `Loader::load()`。如果你希望做严格类型校验，可以分别使用 `load_dylib()`、`load_exec()` 和 `load_object()`。

## 核心能力

| 能力                 | Relink 提供什么                                                                                                           |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| 动态链接期优化       | 先扫描依赖与 section，再在映射前运行 pass；配合 `--emit-relocs` 可做布局重排、hot code 聚集和自定义优化                   |
| 可定制依赖与符号策略 | 调用方控制 `DT_NEEDED` 解析、符号查找顺序、符号拦截和运行时作用域                                                         |
| 隔离的链接上下文     | 每个 `LinkContext` 都是独立的模块仓库、依赖图和重定位作用域；需要共享时再显式 `snapshot()` 或 `extend()`                  |
| Section 级布局规划   | 对支持重排修复的模块，可在映射前以 section 为单位分配 placement / arena，并按内存类别、页大小和共享策略决定最终运行时映射 |
| 异构与低层环境加载   | 支持不同 ELF 布局、ABI 或目标架构镜像的扫描与装载，并保留 `no_std` 友好的核心设计                                         |
| 类型安全符号访问     | 通过与已加载镜像生命周期绑定的类型化符号接口减少悬垂符号风险                                                              |
| 混合链接             | 在同一运行时加载流程中组合共享对象、可执行镜像和可重定位对象                                                              |
| 可替换映射后端       | 映射层可由调用方接入不同平台、权限模型或大页策略                                                                          |

### 和常见方案相比

| 能力             | Relink                                                                 | `dlopen` 风格加载          |
| ---------------- | ---------------------------------------------------------------------- | -------------------------- |
| 内存加载         | 支持：路径、内存缓冲区和已解析 ELF 输入                                | 通常不方便或不可用         |
| `ET_REL` 加载    | 支持：feature-gated 的可重定位对象加载                                 | 不支持                     |
| 链接前规划       | 支持：先扫描依赖和 section，再决定映射、arena、page size 与重定位策略  | 不支持                     |
| 动态链接期优化   | 支持：配合 `--emit-relocs` 做 section 重排、hot code 聚集和自定义 pass | 不支持                     |
| 大页与映射策略   | 支持：映射后端可接入大页、权限和平台相关策略                           | 通常不可控                 |
| 依赖与符号策略   | 支持：调用方控制依赖图、作用域、符号查找和重定位拦截                   | 通常不可控                 |
| 链接上下文隔离   | 支持：多个 `LinkContext` 可承载彼此隔离的依赖图和符号作用域            | 通常依赖进程级链接器状态   |
| 异构加载         | 支持：面向不同 ELF 布局、ABI 或目标架构镜像的扫描与装载                | 依赖宿主平台动态链接器能力 |
| 符号生命周期安全 | 支持：类型化符号与已加载镜像生命周期绑定                               | 不支持                     |

## 快速开始

默认 feature 集合适合直接加载动态库、可执行文件和处理 TLS：

```toml
[dependencies]
elf_loader = "0.14.1"
```

如果你希望一次打开常见高级能力，可以启用 `full`：

```toml
[dependencies]
elf_loader = { version = "0.14.1", features = ["full"] }
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

## 加载路径一览

| 路径            | 入口                                                     | 适合                                                                                        |
| --------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| 直接加载        | `Loader::load_dylib()` / `load_exec()` / `load_object()` | 已经知道要加载哪个镜像，只需要自定义符号查找、scope、TLS、lazy binding 或重定位 hook        |
| 运行时依赖链接  | `Linker::load()`                                         | 需要 `KeyResolver` 和 `LinkContext` 管理依赖图、作用域和上下文隔离，但不需要映射前布局 pass |
| Scan-first 链接 | `Linker::load_scan_first()`                              | 需要先发现 `DT_NEEDED` 依赖图，再运行布局 pass、选择物化策略并统一重定位                    |
| 可重定位对象    | `Loader::load_object()`                                  | 需要在运行时组合 `.o` 与 `.so`；需要开启 `object` feature                                   |
| 自定义映射环境  | `Loader::with_mmap()` / `with_page_size()`               | 需要接入自己的 mmap、权限模型、页大小或大页策略                                             |

直接加载路径更短，适合插件和工具型场景。`Linker::load()` 适合需要独立依赖图和作用域的运行时加载；scan-first 路径更适合服务器、运行时和内核这类需要先规划再映射的场景。

## 典型工作流

### 从内存加载

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

如果你不需要自定义显示名，也可以直接使用 `load_dylib(&bytes)` 或 `load_exec(&bytes)`。

### 宿主符号、作用域与 lazy binding

Relink 的重定位阶段可以由调用方提供符号策略：

- `pre_find_fn()` / `post_find_fn()`：在目标镜像自身符号查找前后注入宿主符号。
- `scope()` / `add_scope()`：把已经加载的对象加入当前镜像的搜索作用域。
- `pre_handler()` / `post_handler()`：在重定位写入前后拦截请求。
- `share_find_with_lazy()`：让 lazy binding 的 PLT fixup 复用初始重定位阶段的查找规则。
- `lazy_pre_find_fn()` / `lazy_post_find_fn()`：为 lazy fixup 单独配置符号查找策略。

`lazy binding` 相关接口需要开启 `lazy-binding` feature。

### 使用 Linker 管理运行时依赖图

当加载不再是“打开一个文件”时，可以使用 `Linker`。它通过 `KeyResolver` 解析根模块和 `DT_NEEDED` 依赖，并把加载结果提交到调用方提供的 `LinkContext`，让不同加载域拥有彼此隔离的依赖图和符号作用域。

| 部件              | 作用                                                                                |
| ----------------- | ----------------------------------------------------------------------------------- |
| `KeyResolver`     | 把根 key 和 `DT_NEEDED` 名称解析成具体 ELF 输入                                     |
| `LinkContext`     | 保存一组彼此隔离的已加载模块、依赖关系和符号作用域；不同 context 不会自动共享状态   |
| `LinkPipeline`    | 在 `load_scan_first()` 的映射前运行 pass，修改布局、materialization 或 section 数据 |
| `map_relocator()` | 在最终重定位前配置宿主符号、scope、lazy binding 或 relocation handler               |

`Linker` 提供两条加载接口：

| 接口                        | 行为                                                                         |
| --------------------------- | ---------------------------------------------------------------------------- |
| `Linker::load()`            | 加载时解析依赖并重定位，适合只需要依赖图、作用域和 context 隔离的场景        |
| `Linker::load_scan_first()` | 先扫描完整依赖组并构建可修改的 link plan，适合映射前布局规划和动态链接时优化 |

最小使用方式是实现一个 resolver，然后把 root key 交给 `load()`：

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

需要布局优化时，改用 `load_scan_first()` 并在 `map_pipeline()` 里追加 pass；需要宿主符号或重定位拦截时，在 `map_relocator()` 里配置对应策略。

### 动态链接期优化和大页布局

如果你希望在运行时重排 section，目标 ELF 需要在链接阶段保留重定位信息。常见做法是在构建目标动态库或可执行镜像时把 `--emit-relocs` 传给链接器，例如通过 `-Wl,--emit-relocs`。

scan-first pass 可以在映射前查看 section、修改数据、调整 materialization，并把代码、只读数据、可写数据或 TLS 放进不同的 arena。对于追求极致性能的服务器应用，常见策略包括：

| 优化方向     | 可以在 pass 中做什么                                                     |
| ------------ | ------------------------------------------------------------------------ |
| 热代码聚集   | 将 hot code section 放入同一段更紧凑的可执行 arena，减少运行时局部性损失 |
| 大页映射     | 为代码或只读数据 arena 选择 `Huge2MiB` / `Huge1GiB` 等页大小             |
| 自定义布局   | 按 profile、模块来源、符号分组或业务策略重新安排 section placement       |
| 重定位期改写 | 利用保留的重定位信息，在映射和最终重定位前修正受布局变化影响的元数据     |

完整的 scan-first 加载流程见 `cargo run --example load_scan_first`。如果要写自己的布局优化 pass，可以从 `LinkPipeline`、`ReorderPass`、`ArenaDescriptor` 和 `Section` 这些接口开始。

### 混合 `.o` 和 `.so`

开启 `object` feature 后，可以先加载可重定位对象，再把它作为后续动态库的搜索作用域：

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


## Feature 开关

| Feature           | 默认 | 作用                                                           |
| ----------------- | ---- | -------------------------------------------------------------- |
| `libc`            | 是   | 在 Unix-like 平台使用 libc 后端                                |
| `tls`             | 是   | 启用 TLS 重定位处理和内置 TLS resolver                         |
| `lazy-binding`    | 否   | 启用 PLT/GOT lazy binding 和 lazy fixup 查找配置               |
| `object`          | 否   | 启用可重定位目标文件（`ET_REL`）加载和 `Loader::load_object()` |
| `version`         | 否   | 启用带符号版本的查找，例如 `get_version()`                     |
| `log`             | 否   | 启用基于 `log` 的加载与重定位诊断输出                          |
| `portable-atomic` | 否   | 为不支持原生指针宽度原子操作的目标提供支持                     |
| `use-syscall`     | 否   | 在 Linux 上使用 syscall 后端，而不是 libc                      |
| `full`            | 否   | 便捷组合：`tls`、`lazy-binding`、`object`、`libc`              |

说明：

- 默认 feature 是 `tls` + `libc`。
- 仅仅编译进 `tls` 还不够。如果目标 ELF 实际使用 TLS 重定位，加载时需要从 `Loader::new().with_default_tls_resolver()` 开始，或者提供你自己的 TLS resolver。
- `load_object()` 是 feature-gated 的。默认 feature 下直接运行 `cargo run --example load_object` 会失败，需要加上 `--features object`。

## 示例

[`examples/`](examples/) 目录覆盖了主要扩展点：

| 示例                 | 展示内容                                                | 运行方式                                            |
| -------------------- | ------------------------------------------------------- | --------------------------------------------------- |
| `load_dylib`         | 加载共享对象并解析宿主符号                              | `cargo run --example load_dylib`                    |
| `from_memory`        | 从字节缓冲区加载 ELF                                    | `cargo run --example from_memory`                   |
| `load_exec`          | 查看可执行文件的入口地址和基址                          | `cargo run --example load_exec`                     |
| `load_hook`          | 用 `with_hook()` 观察段加载                             | `cargo run --example load_hook`                     |
| `load_scan_first`    | 发现 `DT_NEEDED`、运行 scan-first pass 并配置映射前布局 | `cargo run --example load_scan_first`               |
| `lifecycle`          | 自定义 `.init` / `.fini` 调用流程                       | `cargo run --example lifecycle`                     |
| `user_data`          | 初始化 dynamic image 级上下文                           | `cargo run --example user_data`                     |
| `relocation_handler` | 用自定义 handler 拦截重定位                             | `cargo run --example relocation_handler`            |
| `load_object`        | 加载可重定位目标文件                                    | `cargo run --example load_object --features object` |

## 平台说明

| 架构                                                              | 动态库 / 可执行文件 | 动态链接时优化                                  | `.o` / `ET_REL`    |
| ----------------------------------------------------------------- | ------------------- | ----------------------------------------------- | ------------------ |
| `x86_64`                                                          | ✅ 主要验证路径      | ✅ 布局 pass / placement / hot code / 大页 arena | ✅ `object` feature |
| `x86` / `aarch64` / `arm` / `riscv64` / `riscv32` / `loongarch64` | ✅                   | 🟡 基础依赖规划；复杂重排待补                    | ⏳ 待实现           |

符号：✅ 支持，🟡 基础支持，⏳ 待实现。复杂 section 重排修复和 `.o` / `ET_REL` 目前主要围绕 `x86_64` 的重定位实现展开；其他架构欢迎补齐。

- 符号查找按导出名精确匹配，不会替你做 Rust 名字改编。需要稳定运行时符号名时，建议导出 C ABI 符号。

## 参与贡献

欢迎通过 Issue 和 PR 一起把 Relink 做得更扎实，尤其欢迎补充平台支持和文档示例。

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
