# Relink：高效运行时链接

<p align="center">
<img src="./docs/imgs/logo.png" width="500" alt="Relink Logo">
<br>
</p>

<p align="center">
<a href="https://crates.io/crates/elf_loader"><img src="https://img.shields.io/crates/v/elf_loader.svg" alt="Crates.io"></a>
<a href="https://crates.io/crates/elf_loader"><img src="https://img.shields.io/crates/d/elf_loader.svg" alt="Crates.io"></a>
<a href="https://docs.rs/elf_loader"><img src="https://docs.rs/elf_loader/badge.svg" alt="Docs.rs"></a>
<img src="https://img.shields.io/badge/rust-1.93.0+-blue.svg" alt="Min. Rust Version">
<a href="https://github.com/weizhiao/rust-elfloader/actions"><img src="https://github.com/weizhiao/rust-elfloader/actions/workflows/rust.yml/badge.svg" alt="Build Status"></a>
<img src="https://img.shields.io/crates/l/elf_loader.svg" alt="License MIT/Apache-2.0">
</p>

---

## 🚀 为什么选择 Relink？

`Relink` 是一款专为 Rust 生态打造的高性能运行时链接器（JIT Linker）。它不仅能够从传统文件系统，也能直接从内存映像中高效解析各类 ELF 格式，并执行灵活的动态与静态混合链接。

无论是开发操作系统内核、嵌入式系统、JIT 编译器，还是构建插件化应用，Relink 都能以零成本抽象、高效执行和强大扩展性，为您的项目提供坚实支撑。

---

## 🔥 关键特性

### 🛡️ 内存安全
借助 Rust 的所有权系统与智能指针，Relink 确保了运行时的安全性。
* **生命周期绑定**：获取的符号（Symbol）携带生命周期标记，编译器确保其不会超出库的存活范围，**根除 `use-after-free`**。
* **自动依赖管理**：使用 `Arc` 自动维护库之间的依赖关系，防止被依赖的库过早释放。

```rust
// 🛡️ 编译器级安全屏障：
let sym = unsafe { lib.get::<fn()>("plugin_fn")? };
drop(lib); // 💥 试图在这里卸载库...
// sym();  // 🛑 编译失败！Relink 成功拦截了这次潜在的 Use-After-Free 崩溃。
```

### 🔀 混合链接能力
打破动态库与静态库的界限，支持将 **可重定位目标文件 (`.o`)** 与 **动态链接库 (`.so`)** 进行混合链接。你可以像加载动态库一样加载 `.o` 文件，并将其中的未定义符号动态链接到系统或其他已加载的库中。

### 🎭 深度定制与符号拦截
通过实现 `SymbolLookup` trait 和 `RelocationHandler` trait，用户可以深度介入链接过程。
* **符号拦截与替换**：在加载时拦截并替换库的外部依赖符号，轻松实现函数打桩 (Mock) 或行为监控。
* **自定义链接逻辑**：完全掌控符号解析策略，构建灵活的插件系统。

### ⚡ 极致性能与全场景支持
* **高性能**：基于 Rust 的零成本抽象，提供接近原生的加载与符号解析速度。
* **`no_std` 兼容**：核心库无 OS 依赖，完美适配 **操作系统内核**、**嵌入式设备** 及 **裸机开发**。
* **现代特性**：支持 **RELR** 等现代 ELF 特性，优化内存占用与启动时间；支持延迟绑定，优化大型动态库的加载速度。

---

## 🎯 它能做什么？

| 场景                   | Relink 带来的变革                                                              |
| :--------------------- | :----------------------------------------------------------------------------- |
| **插件化架构**         | 实现比 `dlopen` 更安全、粒度更细的动态模块加载与隔离，支持 `.o` 直接作为插件。 |
| **JIT 编译器与运行时** | 即时链接编译好的机器码片段，无需手动管理代码位置，极大简化 JIT 实现。          |
| **操作系统/内核开发**  | 提供高质量的用户态程序加载器原型，或用于实现内核模块的动态加载。               |
| **游戏/引擎热重载**    | 动态替换游戏逻辑模块，实现“代码即改即生效”的流畅开发体验。                     |
| **嵌入式/边缘计算**    | 在资源受限的设备上，实现固件模块的安全热更新与动态组合。                       |
| **安全研究与逆向**     | 通过 Hook 机制，无侵入地分析二进制文件的行为与交互。                           |

---

## 🚀 即刻上手

### 添加到你的项目
```toml
[dependencies]
elf_loader = "0.14"
```

### 基础示例：加载并调用一个动态库
```rust
use elf_loader::load_dylib;

fn main() {
    // 1. 加载库并执行即时链接
    let lib = Loader::new()
        .load_dylib("path/to/your_library.so")?
        .relocator()
        // 可选：提供自定义符号解析（例如，从主程序导出符号）
        .pre_find_fn(|sym_name| {
            if sym_name == "my_host_function" {
                Some(my_host_function as *const ())
            } else {
                None
            }
        })
        .relocate()?; // 完成所有重定位

    // 2. 安全地获取并调用函数
    let awesome_func = unsafe { lib.get::<fn(i32) -> i32>("awesome_func")? };
    let result = awesome_func(42);
    println!("结果: {}", result);
}

// 一个可以被插件调用的宿主函数
extern "C" fn my_host_function(value: i32) -> i32 {
    value * 2
}
```

> **💡 提示**：想要探索更多高级特性（如生命周期钩子、重定向拦截、定义额外的用户数据等）？请参考 [examples](examples/) 目录下的详细示例。

---

## 📊 平台支持

Relink 致力于跨平台支持。

| 架构             | 动态链接 | 延迟绑定 | 混合链接 (.o) |
| :--------------- | :------: | :------: | :-----------: |
| **x86_64**       |    ✅     |    ✅     |       ✅       |
| **x86**          |    ✅     |    ✅     |       🔶       |
| **AArch64**      |    ✅     |    ✅     |       🔶       |
| **Arm**          |    ✅     |    ✅     |       🔶       |
| **RISC-V 64/32** |    ✅     |    ✅     |       🔶       |
| **LoongArch64**  |    ✅     |    ✅     |       🔶       |

---

## 🤝 参与贡献

如果你对底层技术、二进制安全或链接器感兴趣，欢迎加入我们！

* **提交 Issue**：反馈 Bug 或提出你的天才构想。

* **Star 我们的项目**：这是对开发者最直接的赛博鼓励。⭐

* **代码贡献**：期待你的 PR，一起构建 Rust 的运行时链接器。

---

## 📜 许可证

本项目采用双重许可：
* **[MIT License](LICENSE-MIT)** - 适用于大多数场景。
* **[Apache License 2.0](LICENSE-APACHE)** - 适用于需要专利保护的项目。

你可以根据需求选择其一。

---

## 🎈 开发者

<a href="https://github.com/weizhiao/rust-elfloader/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=weizhiao/rust-elfloader" alt="项目贡献者" />
</a>

---

**Relink — 为您的项目带来高效的运行时链接能力。** 🚀

---