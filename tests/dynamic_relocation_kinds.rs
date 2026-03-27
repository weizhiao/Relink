mod support;

use elf_loader::{
    Loader,
    arch::{REL_COPY, REL_IRELATIVE, REL_RELATIVE},
    input::ElfBinary,
};
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
fn copy_relocation_copies_bytes() {
    let mut loader = Loader::new();
    let helper_output = write_test_dylib(
        &[],
        &[SymbolDesc::global_object(
            COPY_SOURCE_NAME,
            &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
        )],
    );
    let helper = load_relocated_dylib(&mut loader, "libcopy_source.so", &helper_output);

    let consumer_output = write_test_dylib(
        &[RelocEntry::copy(COPY_SOURCE_NAME, Arch::current())],
        &[SymbolDesc::undefined_object(COPY_SOURCE_NAME).with_size(6)],
    );

    let relocated = loader
        .load_dylib(ElfBinary::new("copy_consumer.so", &consumer_output.data))
        .expect("failed to load copy consumer")
        .relocator()
        .scope(&[helper.clone()])
        .relocate()
        .expect("failed to relocate copy consumer");

    let copy = relocation_for_symbol(&consumer_output, REL_COPY, COPY_SOURCE_NAME);
    assert_eq!(copy.section, SectionKind::Data);
    assert_eq!(
        relocated.deps().len(),
        1,
        "expected one retained dependency"
    );
    assert_eq!(relocated.deps()[0].name(), helper.name());

    unsafe {
        let src = helper
            .get::<u8>(COPY_SOURCE_NAME)
            .expect("missing copy source")
            .into_raw();
        let dst = slot_address(&relocated, copy) as *const u8;
        assert_eq!(
            std::slice::from_raw_parts(dst, copy.sym_size as usize),
            std::slice::from_raw_parts(src as *const u8, copy.sym_size as usize)
        );
    }
}

#[test]
fn relative_relocation_uses_recorded_addend() {
    let output = write_test_dylib(&[RelocEntry::relative(Arch::current())], &[]);

    let relocated = Loader::new()
        .load_dylib(ElfBinary::new("relative.so", &output.data))
        .expect("failed to load relative test dylib")
        .relocator()
        .relocate()
        .expect("failed to relocate relative test dylib");

    let relative = anonymous_relocations(&output, REL_RELATIVE)[0];
    assert_eq!(relative.section, SectionKind::Got);
    assert_eq!(
        slot_word(&relocated, relative),
        (relocated.base() as i64 + relative.addend) as u64
    );
    assert!(
        relocated.deps().is_empty(),
        "relative relocations should not retain dependencies"
    );
}

#[test]
fn irelative_relocation_uses_ifunc_resolver() {
    let resolver_offset = 0x88;
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default().with_ifunc_resolver_val(resolver_offset),
        &[RelocEntry::irelative(Arch::current())],
        &[],
    );

    let relocated = Loader::new()
        .load_dylib(ElfBinary::new("irelative.so", &output.data))
        .expect("failed to load irelative test dylib")
        .relocator()
        .relocate()
        .expect("failed to relocate irelative test dylib");

    let irelative = anonymous_relocations(&output, REL_IRELATIVE)[0];
    assert_eq!(irelative.section, SectionKind::Got);
    assert_eq!(
        slot_word(&relocated, irelative),
        relocated.base() as u64 + resolver_offset
    );
    assert!(
        relocated.deps().is_empty(),
        "irelative relocations should not retain dependencies"
    );
}

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

    let relocated = loader
        .load_dylib(ElfBinary::new(
            "copy_consumer_many.so",
            &consumer_output.data,
        ))
        .expect("failed to load copy consumer")
        .relocator()
        .scope(&[helper.clone()])
        .relocate()
        .expect("failed to relocate copy consumer");

    assert_eq!(
        relocated.deps().len(),
        1,
        "expected one retained dependency"
    );
    assert_eq!(relocated.deps()[0].name(), helper.name());

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

    let relocated = Loader::new()
        .load_dylib(ElfBinary::new("relative_many.so", &output.data))
        .expect("failed to load relative test dylib")
        .relocator()
        .relocate()
        .expect("failed to relocate relative test dylib");

    let relatives = anonymous_relocations(&output, REL_RELATIVE);
    assert_eq!(relatives.len(), 3, "expected three relative relocations");
    for relative in relatives {
        assert_eq!(relative.section, SectionKind::Got);
        assert_eq!(
            slot_word(&relocated, relative),
            (relocated.base() as i64 + relative.addend) as u64
        );
    }
    assert!(
        relocated.deps().is_empty(),
        "relative relocations should not retain dependencies"
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

    let relocated = Loader::new()
        .load_dylib(ElfBinary::new("irelative_many.so", &output.data))
        .expect("failed to load irelative test dylib")
        .relocator()
        .relocate()
        .expect("failed to relocate irelative test dylib");

    let irelatives = anonymous_relocations(&output, REL_IRELATIVE);
    assert_eq!(irelatives.len(), 2, "expected two irelative relocations");
    for irelative in irelatives {
        assert_eq!(irelative.section, SectionKind::Got);
        assert_eq!(
            slot_word(&relocated, irelative),
            relocated.base() as u64 + resolver_offset
        );
    }
    assert!(
        relocated.deps().is_empty(),
        "irelative relocations should not retain dependencies"
    );
}
