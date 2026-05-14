mod support;

#[cfg(all(feature = "object", target_arch = "x86_64"))]
use gen_elf::{ObjectElfOutput, RelocationInfo, SectionKind};

#[cfg(all(feature = "object", target_arch = "x86_64"))]
fn relocation_for_symbol<'a>(
    output: &'a ObjectElfOutput,
    r_type: u32,
    symbol_name: &str,
) -> &'a RelocationInfo {
    output
        .find_relocation(r_type, symbol_name)
        .unwrap_or_else(|| {
            panic!(
                "missing relocation type {} for symbol {}",
                r_type, symbol_name
            )
        })
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
fn anonymous_relocation(output: &ObjectElfOutput, r_type: u32) -> &RelocationInfo {
    output
        .relocations
        .iter()
        .find(|reloc| reloc.r_type == r_type && reloc.symbol_name.is_none())
        .unwrap_or_else(|| panic!("missing relocation type {} without symbol", r_type))
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
fn assert_data_section(reloc: &RelocationInfo) {
    assert_eq!(reloc.section, SectionKind::Data);
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn object_relocations_match() {
    use gen_elf::{Arch, ObjectWriter, RelocEntry, SymbolDesc};
    use support::{
        host_symbols::{
            EXTERNAL_FUNC_NAME, EXTERNAL_TLS_NAME, EXTERNAL_VAR_NAME, LOCAL_VAR_NAME,
            TestHostSymbols,
        },
        memory::{read_i32, read_u64},
    };

    let arch = Arch::current();
    debug_assert_eq!(arch, Arch::X86_64);

    let symbols = vec![
        SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x100]),
        SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME),
        SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
        SymbolDesc::undefined_object(EXTERNAL_TLS_NAME),
    ];

    let relocs = vec![
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, 1),
        RelocEntry::with_name(EXTERNAL_VAR_NAME, 9),
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, 9),
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, 4),
        RelocEntry::new(1),
        RelocEntry::with_name(EXTERNAL_VAR_NAME, 1),
    ];

    let object_file = ObjectWriter::new(arch)
        .write(&symbols, &relocs)
        .expect("failed to generate static ELF");
    let host_symbols = TestHostSymbols::new();

    let loaded_object = elf_loader::Loader::new()
        .load_object(elf_loader::input::ElfBinary::new(
            "test_static.o",
            &object_file.data,
        ))
        .expect("failed to load object")
        .relocator()
        .scope([host_symbols.source("__host")])
        .relocate()
        .expect("relocation failed");

    let data_base =
        unsafe { loaded_object.get::<i32>(LOCAL_VAR_NAME).unwrap().into_raw() } as usize;
    let external_func_addr = host_symbols.addresses[EXTERNAL_FUNC_NAME];
    let external_var_addr = host_symbols.addresses[EXTERNAL_VAR_NAME];

    let assert_absolute_slot = |relocation: &RelocationInfo, expected: usize, message: &str| {
        assert_data_section(relocation);
        let slot = (data_base + relocation.offset as usize) as *const u8;
        let actual = read_u64(slot) as usize;
        assert_eq!(actual, expected, "{message}");
    };

    let assert_gotpcrel_target = |relocation: &RelocationInfo, expected: usize, message: &str| {
        assert_data_section(relocation);
        let slot = (data_base + relocation.offset as usize) as *const u8;
        let target = (slot as usize).wrapping_add(read_i32(slot) as usize);
        let actual = read_u64(target as *const u8) as usize;
        assert_eq!(actual, expected, "{message}");
    };

    assert_absolute_slot(
        relocation_for_symbol(&object_file, 1, EXTERNAL_FUNC_NAME),
        external_func_addr,
        "R_X86_64_64 func mismatch",
    );
    assert_gotpcrel_target(
        relocation_for_symbol(&object_file, 9, EXTERNAL_VAR_NAME),
        external_var_addr,
        "R_X86_64_GOTPCREL var mismatch",
    );
    assert_gotpcrel_target(
        relocation_for_symbol(&object_file, 9, EXTERNAL_FUNC_NAME),
        external_func_addr,
        "R_X86_64_GOTPCREL func mismatch",
    );

    let plt_relocation = relocation_for_symbol(&object_file, 4, EXTERNAL_FUNC_NAME);
    let slot = (data_base + plt_relocation.offset as usize) as *const u8;
    let target = (slot as usize).wrapping_add(read_i32(slot) as usize);
    if target != external_func_addr {
        assert_eq!(
            read_u64(target as *const u8) & 0xffffffff,
            0xfa1e0ff3,
            "PLT signature mismatch"
        );
    }

    assert_absolute_slot(
        anonymous_relocation(&object_file, 1),
        data_base,
        "R_X86_64_64 relative mismatch",
    );
    assert_absolute_slot(
        relocation_for_symbol(&object_file, 1, EXTERNAL_VAR_NAME),
        external_var_addr,
        "R_X86_64_64 absolute mismatch",
    );
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn object_addends_apply() {
    use gen_elf::{Arch, ObjectWriter, RelocEntry, SymbolDesc};
    use support::{
        host_symbols::{EXTERNAL_VAR_NAME, LOCAL_VAR_NAME, TestHostSymbols},
        memory::read_u64,
    };

    let arch = Arch::current();
    debug_assert_eq!(arch, Arch::X86_64);

    let object_file = ObjectWriter::new(arch)
        .write(
            &[
                SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x40]),
                SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
            ],
            &[RelocEntry::with_name(EXTERNAL_VAR_NAME, 1).with_addend(0x20)],
        )
        .expect("failed to generate object with addend relocation");
    let host_symbols = TestHostSymbols::new();

    let loaded_object = elf_loader::Loader::new()
        .load_object(elf_loader::input::ElfBinary::new(
            "test_static_addend.o",
            &object_file.data,
        ))
        .expect("failed to load object")
        .relocator()
        .scope([host_symbols.source("__host")])
        .relocate()
        .expect("relocation failed");

    let data_base =
        unsafe { loaded_object.get::<i32>(LOCAL_VAR_NAME).unwrap().into_raw() } as usize;
    let relocation = relocation_for_symbol(&object_file, 1, EXTERNAL_VAR_NAME);
    assert_data_section(relocation);

    let actual = read_u64((data_base + relocation.offset as usize) as *const u8) as usize;
    let expected = host_symbols.addresses[EXTERNAL_VAR_NAME] + relocation.addend as usize;
    assert_eq!(actual, expected, "R_X86_64_64 addend mismatch");
}
