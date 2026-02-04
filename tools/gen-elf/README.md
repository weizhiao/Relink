# gen-elf

`gen-elf` is a utility for generating ELF files (Shared Objects and Relocatable Objects) specifically designed for testing ELF loaders. It simplifies the process of creating binaries with specific symbol structures, relocation entries, and memory layouts for `elf_loader` verification.

## Features

- **Multi-architecture Support**: Supports x86_64, x86, Aarch64, Riscv64, Riscv32, Arm, and Loongarch64.
- **Dynamic Library Generation**: Generates Shared Objects (.so) with `.dynamic` sections, relocation tables (RELA/REL), symbol tables, and GOT/PLT.
- **TLS and IFUNC Support**: Easily generate Thread-Local Storage (TLS) symbols and Indirect Functions (IFUNC) with automatic resolver generation.
- **Relocatable Object Generation**: Generates standard relocatable object files (.o).
- **Customizable Layout**: Configure base address and page size for memory mapping tests.
- **Metadata Export**: Exports detailed relocation information and section addresses alongside the ELF data for easy verification in tests.

## Core Interfaces

### `DylibWriter`
Used for generating dynamic libraries. You can customize the generation using `ElfWriterConfig`.

```rust
use gen_elf::{Arch, DylibWriter, ElfWriterConfig, RelocEntry, SymbolDesc};

let arch = Arch::current();
let config = ElfWriterConfig::default()
    .with_base_addr(0x400000)
    .with_page_size(0x1000);
let writer = DylibWriter::with_config(arch, config);

let relocs = vec![
    RelocEntry::jump_slot("external_func", arch),
    RelocEntry::irelative(arch), // Test IFUNC
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
Used for generating relocatable object files.

```rust
use gen_elf::{Arch, ObjectWriter, SymbolDesc};

let arch = Arch::X86_64;
let writer = ObjectWriter::new(arch);

let symbols = vec![
    SymbolDesc::global_func("my_func", &[0x90, 0xc3]), // nop; ret
    SymbolDesc::global_object("data_var", &[0x01, 0x02]),
];

// Symbols and Relocs
writer.write_file("test.o", &symbols, &[])?;
```

### `RelocEntry`
Common relocation types are available as high-level methods:

- `RelocEntry::jump_slot(name, arch)`: PLT-based functions.
- `RelocEntry::glob_dat(name, arch)`: Global variable references.
- `RelocEntry::relative(arch)`: Base-relative relocations.
- `RelocEntry::irelative(arch)`: Indirect (IFUNC) relocations.
- `RelocEntry::copy(name, arch)`: Copy relocations for variables.
- `RelocEntry::dtpmod(name, arch)` / `RelocEntry::dtpoff(name, arch)`: TLS-related relocations.

### `SymbolDesc`
Describe symbols with various scopes and types:

- `SymbolDesc::global_func(name, code)`: A global function.
- `SymbolDesc::global_object(name, data)`: A global variable.
- `SymbolDesc::global_tls(name, data)`: A thread-local variable.
- `SymbolDesc::undefined_func(name)`: Reference to an external function.
- `.with_scope(SymbolScope::Weak)`: Mark a symbol as weak.

## Usage in Tests

This tool is particularly useful for integration testing of `elf_loader`. You can dynamically generate an ELF with specific relocation types, load it with your loader, and verify that relocations are applied correctly by inspecting `ElfWriteOutput`.

See `tests/gen_elf.rs` for comprehensive examples.
