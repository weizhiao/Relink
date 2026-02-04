# gen-elf

`gen-elf` 是一个用于生成测试用 ELF 文件（共享对象和可重定位对象）的辅助工具，专为测试 ELF 加载器而设计。它简化了创建具有特定符号结构、重定位条目和内存布局的二进制文件的过程，以便对 `elf_loader` 进行验证。

## 功能特性

- **多架构支持**：支持 x86_64, x86, Aarch64, Riscv64, Riscv32, Arm 和 Loongarch64。
- **动态库生成**：生成带有 `.dynamic` 段、重定位表（RELA/REL）、符号表以及 GOT/PLT 的共享对象 (.so)。
- **TLS 和 IFUNC 支持**：轻松生成线程本地存储 (TLS) 符号和间接函数 (IFUNC)，并自动生成 resolver。
- **可重定位对象生成**：生成标准的可重定位对象文件 (.o)。
- **可自定义布局**：配置用于内存映射测试的基地址和页面大小。
- **元数据导出**：导出详细的重定位信息和段地址，方便在测试中进行验证。

## 核心接口

### `DylibWriter`
用于生成动态库。你可以使用 `ElfWriterConfig` 自定义生成过程。

```rust
use gen_elf::{Arch, DylibWriter, ElfWriterConfig, RelocEntry, SymbolDesc};

let arch = Arch::current();
let config = ElfWriterConfig::default()
    .with_base_addr(0x400000)
    .with_page_size(0x1000);
let writer = DylibWriter::with_config(arch, config);

let relocs = vec![
    RelocEntry::jump_slot("external_func", arch),
    RelocEntry::irelative(arch), // 测试 IFUNC
];

let symbols = vec![
    SymbolDesc::global_object("my_var", &[1, 2, 3, 4]),
    SymbolDesc::global_tls("my_tls", &[0xaa, 0xbb]),
    SymbolDesc::undefined_func("external_func"),
];

let output = writer.write(&relocs, &symbols)?;
println!("Generated ELF with {} relocations", output.relocations.len());
```

### `ObjectWriter`
用于生成可重定位对象文件。

```rust
use gen_elf::{Arch, ObjectWriter, SymbolDesc};

let arch = Arch::X86_64;
let writer = ObjectWriter::new(arch);

let symbols = vec![
    SymbolDesc::global_func("my_func", &[0x90, 0xc3]), // nop; ret
    SymbolDesc::global_object("data_var", &[0x01, 0x02]),
];

// 符号和重定位
writer.write_file("test.o", &symbols, &[])?;
```

### `RelocEntry`
常见的重定位类型可以通过高层级方法使用：

- `RelocEntry::jump_slot(name, arch)`：基于 PLT 的函数。
- `RelocEntry::glob_dat(name, arch)`：全局变量引用。
- `RelocEntry::relative(arch)`：基地址相对重定位。
- `RelocEntry::irelative(arch)`：间接 (IFUNC) 重定位。
- `RelocEntry::copy(name, arch)`：变量的复制重定位。
- `RelocEntry::dtpmod(name, arch)` / `RelocEntry::dtpoff(name, arch)`：TLS 相关重定位。

### `SymbolDesc`
描述具有各种作用域和类型的符号：

- `SymbolDesc::global_func(name, code)`：全局函数。
- `SymbolDesc::global_object(name, data)`：全局变量。
- `SymbolDesc::global_tls(name, data)`：线程本地变量。
- `SymbolDesc::undefined_func(name)`：对外部函数的引用。
- `.with_scope(SymbolScope::Weak)`：将符号标记为弱符号 (weak)。

## 在测试中使用

该工具特别适用于 `elf_loader` 的集成测试。你可以动态生成具有特定重定位类型的 ELF，使用加载器加载它，并通过检查 `ElfWriteOutput` 验证重定位是否正确应用。

有关全面示例，请参阅 `tests/gen_elf.rs`。
