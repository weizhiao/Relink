# Relink: High-Performance Runtime Linking

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

<p align="center">
  <a href="README.md">English</a> | <a href="README-zh_cn.md">简体中文</a>
</p>

## 🚀 Why Relink?

**Relink** is a high-performance runtime linker (JIT Linker) tailor-made for the Rust ecosystem. It efficiently parses various ELF formats—not only from traditional file systems but also directly from memory images—and performs flexible dynamic and static hybrid linking.

Whether you are developing **OS kernels**, **embedded systems**, **JIT compilers**, or building **plugin-based applications**, Relink provides a solid foundation with zero-cost abstractions, high-speed execution, and powerful extensibility.

---

## 🔥 Key Features

### 🛡️ Memory Safety

Leveraging Rust's ownership system and smart pointers, Relink ensures safety at runtime.

* **Lifetime Binding**: Symbols retrieved from a library carry lifetime markers. The compiler ensures they do not outlive the library itself, **erasing `use-after-free` risks**.
* **Automatic Dependency Management**: Uses `Arc` to automatically maintain dependency trees between libraries, preventing a required library from being dropped prematurely.

```rust
// 🛡️ The compiler protects you:
let sym = unsafe { lib.get::<fn()>("plugin_fn")? };
drop(lib); // If the library is dropped here...
// sym();  // ❌ Compilation Error! The symbol's lifetime ends with the library.

```

### 🔀 Hybrid Linking Capability

Relink supports mixing **Relocatable Object files (`.o`)** and **Dynamic Shared Objects (`.so`)**. You can load a `.o` file just like a dynamic library and link its undefined symbols to the system or other loaded libraries at runtime.

### 🎭 Deep Customization & Interception

By implementing the `SymbolLookup` and `RelocationHandler` traits, users can deeply intervene in the linking process.

* **Symbol Interception**: Intercept and replace external dependency symbols during loading. Perfect for function mocking, behavioral monitoring, or hot-patching.
* **Custom Linking Logic**: Take full control over symbol resolution strategies to build highly flexible plugin systems.

### ⚡ Extreme Performance & Versatility

* **Zero-Cost Abstractions**: Built with Rust to provide near-native loading and symbol resolution speeds.
* **`no_std` Support**: The core library has no OS dependencies, making it ideal for **OS kernels**, **embedded devices**, and **bare-metal development**.
* **Modern Features**: Supports **RELR** for modern ELF optimization; supports **Lazy Binding** to improve cold-start times for large dynamic libraries.

---

## 🎯 Use Cases

| Scenario                      | The Relink Advantage                                                                                        |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **Plugin Architectures**      | Enables safer, finer-grained dynamic module loading than `dlopen`, supporting `.o` files as direct plugins. |
| **JIT Compilers & Runtimes**  | Instantly link compiled machine code fragments without manual memory offset management.                     |
| **OS/Kernel Development**     | Provides a high-quality loader prototype for user-space programs or dynamic kernel module loading.          |
| **Game Engine Hot-Reloading** | Dynamically swap game logic modules for a "code-change-to-live-effect" development experience.              |
| **Embedded & Edge Computing** | Securely update firmware modules or combine features dynamically on resource-constrained devices.           |
| **Security Research**         | Use the Hook mechanism to non-invasively analyze binary behavior and interactions.                          |

---

## 🚀 Getting Started

### Add to your project

```toml
[dependencies]
elf_loader = "0.14"

```

### Basic Example: Load and Call a Dynamic Library

```rust
use elf_loader::Loader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load the library and perform instant linking
    let lib = Loader::new()
        .load_dylib("path/to/your_library.so")?
        .relocator()
        // Optional: Provide custom symbol resolution (e.g., export symbols from host)
        .pre_find_fn(|sym_name| {
            if sym_name == "my_host_function" {
                Some(my_host_function as *const ())
            } else {
                None
            }
        })
        .relocate()?; // Complete all relocations

    // 2. Safely retrieve and call the function
    let awesome_func = unsafe { lib.get::<fn(i32) -> i32>("awesome_func")? };
    let result = awesome_func(42);
    println!("Result: {}", result);
    
    Ok(())
}

// A host function that can be called by the plugin
extern "C" fn my_host_function(value: i32) -> i32 {
    value * 2
}
```

> **💡 Tip**: Looking for more advanced features like lifecycle hooks or relocation interception? Check out the [examples](examples/) directory.

---

## 📊 Platform Support

Relink is committed to broad cross-platform support.

| Architecture     | Dynamic Linking | Lazy Binding | Hybrid Linking (.o) |
| ---------------- | --------------- | ------------ | ------------------- |
| **x86_64**       | ✅               | ✅            | ✅                   |
| **x86**          | ✅               | ✅            | 🔶                   |
| **AArch64**      | ✅               | ✅            | 🔶                   |
| **Arm**          | ✅               | ✅            | 🔶                   |
| **RISC-V 64/32** | ✅               | ✅            | 🔶                   |
| **LoongArch64**  | ✅               | ✅            | 🔶                   |

---

## 🤝 Contributing

If you are interested in low-level systems, binary security, or linker internals, we’d love to have you!

* **Open an Issue**: Report bugs or propose your next big idea.
* **Star the Project**: Show your support for the developers! ⭐
* **Code Contributions**: PRs are always welcome—help us build the ultimate Rust runtime linker.

---

## 📜 License

This project is dual-licensed under:

* **[MIT License](https://www.google.com/search?q=LICENSE-MIT)**
* **[Apache License 2.0](https://www.google.com/search?q=LICENSE-APACHE)**

Choose the one that best suits your needs.

---

## 🎈 Contributors

<a href="https://github.com/weizhiao/rust-elfloader/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=weizhiao/rust-elfloader" alt="Project Contributors" />
</a>

---

**Relink — Empowering your projects with high-performance runtime linking.** 🚀

---

