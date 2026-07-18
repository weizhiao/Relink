mod support;

use elf_loader::{
    Loader,
    arch::NativeArch,
    input::ElfBinary,
    memory::VmOffset,
    relocation::{RelocationArch, Relocator},
};

const REL_COPY: u32 = <NativeArch as RelocationArch>::COPY.raw();
const REL_IRELATIVE: u32 = <NativeArch as RelocationArch>::IRELATIVE.raw();
const REL_RELATIVE: u32 = <NativeArch as RelocationArch>::RELATIVE.raw();
use gen_elf::{Arch, ElfWriterConfig, RelocEntry, SectionKind, SymbolDesc};
use support::{
    dylib_relocation_checks::{
        anonymous_relocations, relocation_for_symbol, slot_address, slot_word,
    },
    test_dylib::{load_relocated_dylib, write_test_dylib, write_test_dylib_with_config},
};

const COPY_SOURCE_NAME: &str = "copy_source";
const COPY_SOURCE_NAME2: &str = "copy_source_two";

#[test]
fn copy_relocations_keep_symbols_separate() {
    let mut loader = Loader::new();
    let copy_sources = [
        (COPY_SOURCE_NAME, &[0x10, 0x20, 0x30, 0x40][..]),
        (COPY_SOURCE_NAME2, &[0x55, 0x66, 0x77, 0x88, 0x99][..]),
    ];
    let helper_symbols: Vec<_> = copy_sources
        .iter()
        .map(|(name, bytes)| SymbolDesc::global_object(*name, bytes))
        .collect();
    let helper_output = write_test_dylib(&[], &helper_symbols);
    let helper = load_relocated_dylib(&mut loader, "libcopy_sources.so", &helper_output);

    let consumer_relocations: Vec<_> = copy_sources
        .iter()
        .map(|(name, _)| RelocEntry::copy(*name, Arch::current()))
        .collect();
    let consumer_symbols: Vec<_> = copy_sources
        .iter()
        .map(|(name, bytes)| SymbolDesc::undefined_object(*name).with_size(bytes.len() as u64))
        .collect();
    let consumer_output = write_test_dylib(&consumer_relocations, &consumer_symbols);

    let relocated = Relocator::new()
        .run(
            loader
                .load_dylib(ElfBinary::new(
                    "copy_consumer_many.so",
                    &consumer_output.data,
                ))
                .expect("failed to load copy consumer"),
        )
        .scope(std::slice::from_ref(&helper))
        .relocate()
        .expect("failed to relocate copy consumer");

    let scope = relocated.scope();
    assert_eq!(scope.len(), 1, "expected one retained scope entry");
    assert_eq!(scope[0].name(), helper.name());

    for (name, expected_bytes) in copy_sources {
        let relocation = relocation_for_symbol(&consumer_output, REL_COPY, name);
        assert_eq!(relocation.section, SectionKind::Data);
        unsafe {
            let copied = std::slice::from_raw_parts(
                slot_address(&relocated, relocation) as *const u8,
                relocation.sym_size as usize,
            );
            assert_eq!(copied, expected_bytes, "REL_COPY mismatch for {name}");
        }
    }
}

#[test]
fn relative_relocations_apply_to_all_slots() {
    let output = write_test_dylib(
        &[
            RelocEntry::relative(Arch::current()),
            RelocEntry::relative(Arch::current()),
            RelocEntry::relative(Arch::current()),
        ],
        &[],
    );

    let relocated = Relocator::new()
        .run(
            Loader::new()
                .load_dylib(ElfBinary::new("relative_many.so", &output.data))
                .expect("failed to load relative test dylib"),
        )
        .relocate()
        .expect("failed to relocate relative test dylib");

    let relatives = anonymous_relocations(&output, REL_RELATIVE);
    assert_eq!(relatives.len(), 3, "expected three relative relocations");
    for relative in relatives {
        assert_eq!(relative.section, SectionKind::Got);
        assert_eq!(
            slot_word(&relocated, relative),
            (relocated.base().get() as i64 + relative.addend) as u64
        );
    }
    assert!(
        relocated.scope().is_empty(),
        "relative relocations should not retain scope entries"
    );
}

#[test]
fn irelative_relocations_apply_to_all_slots() {
    let resolver_offset = 0x88;
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default().with_ifunc_resolver_val(resolver_offset),
        &[
            RelocEntry::irelative(Arch::current()),
            RelocEntry::irelative(Arch::current()),
        ],
        &[],
    );

    let relocated = Relocator::new()
        .run(
            Loader::new()
                .load_dylib(ElfBinary::new("irelative_many.so", &output.data))
                .expect("failed to load irelative test dylib"),
        )
        .relocate()
        .expect("failed to relocate irelative test dylib");

    let irelatives = anonymous_relocations(&output, REL_IRELATIVE);
    assert_eq!(irelatives.len(), 2, "expected two irelative relocations");
    for irelative in irelatives {
        assert_eq!(irelative.section, SectionKind::Got);
        assert_eq!(
            slot_word(&relocated, irelative),
            (relocated.base() + VmOffset::new(resolver_offset as usize)).get() as u64
        );
    }
    assert!(
        relocated.scope().is_empty(),
        "irelative relocations should not retain scope entries"
    );
}
