mod support;

use elf_loader::{
    Loader,
    arch::NativeArch,
    image::{LoadedCore, ModuleHandle},
    input::ElfBinary,
    relocation::RelocationArch,
};

const REL_GOT: u32 = <NativeArch as RelocationArch>::GOT.raw();
use gen_elf::{Arch, ElfWriteOutput, RelocEntry, SymbolDesc};
use support::{
    dylib_relocation_checks::{relocation_for_symbol, slot_word},
    host_symbols::{EXTERNAL_VAR_NAME, TestHostSymbols},
    test_dylib::{load_relocated_dylib, write_test_dylib},
};

const SHARED_VAR_NAME: &str = "shared_var";

fn write_helper_dylib(symbol_name: &str, data: &[u8]) -> ElfWriteOutput {
    write_test_dylib(&[], &[SymbolDesc::global_object(symbol_name, data)])
}

fn write_got_consumer(symbol_name: &str) -> ElfWriteOutput {
    let arch = Arch::current();
    write_test_dylib(
        &[RelocEntry::glob_dat(symbol_name, arch)],
        &[SymbolDesc::undefined_object(symbol_name)],
    )
}

fn got_slot_word(image: &LoadedCore<()>, output: &ElfWriteOutput, symbol_name: &str) -> u64 {
    slot_word(image, relocation_for_symbol(output, REL_GOT, symbol_name))
}

fn symbol_address(image: &LoadedCore<()>, symbol_name: &str) -> u64 {
    unsafe {
        image
            .get::<u8>(symbol_name)
            .unwrap_or_else(|| panic!("missing symbol {symbol_name}"))
            .into_raw() as u64
    }
}

#[test]
fn synthetic_module_beats_loaded_scope() {
    let mut loader = Loader::new();
    let helper_output = write_helper_dylib(EXTERNAL_VAR_NAME, &[1, 2, 3, 4]);
    let helper = load_relocated_dylib(&mut loader, "libscope.so", &helper_output);
    let consumer_output = write_got_consumer(EXTERNAL_VAR_NAME);
    let host_symbols = TestHostSymbols::new();

    let relocated = loader
        .load_dylib(ElfBinary::new("consumer.so", &consumer_output.data))
        .expect("failed to load consumer")
        .relocator()
        .scope([
            ModuleHandle::from(host_symbols.source("__host")),
            ModuleHandle::from(&helper),
        ])
        .relocate()
        .expect("failed to relocate consumer");

    assert_eq!(
        got_slot_word(&relocated, &consumer_output, EXTERNAL_VAR_NAME),
        host_symbols.addresses[EXTERNAL_VAR_NAME] as u64
    );
    let deps = relocated.deps().collect::<Vec<_>>();
    assert_eq!(
        deps.len(),
        1,
        "scope entries are retained even when a synthetic module resolves the symbol"
    );
    assert_eq!(deps[0].name(), helper.name());
}

#[test]
fn loaded_scope_beats_late_synthetic_module() {
    let mut loader = Loader::new();
    let helper_output = write_helper_dylib(EXTERNAL_VAR_NAME, &[5, 6, 7, 8]);
    let helper = load_relocated_dylib(&mut loader, "libscope.so", &helper_output);
    let consumer_output = write_got_consumer(EXTERNAL_VAR_NAME);
    let host_symbols = TestHostSymbols::new();

    let relocated = loader
        .load_dylib(ElfBinary::new("consumer.so", &consumer_output.data))
        .expect("failed to load consumer")
        .relocator()
        .scope([
            ModuleHandle::from(&helper),
            ModuleHandle::from(host_symbols.source("__host")),
        ])
        .relocate()
        .expect("failed to relocate consumer");

    assert_eq!(
        got_slot_word(&relocated, &consumer_output, EXTERNAL_VAR_NAME),
        symbol_address(&helper, EXTERNAL_VAR_NAME)
    );
    let deps = relocated.deps().collect::<Vec<_>>();
    assert_eq!(deps.len(), 1, "expected one retained dependency");
    assert_eq!(deps[0].name(), helper.name());
}

#[test]
fn synthetic_module_resolves_scope_miss() {
    let consumer_output = write_got_consumer(EXTERNAL_VAR_NAME);
    let host_symbols = TestHostSymbols::new();

    let relocated = Loader::new()
        .load_dylib(ElfBinary::new("consumer.so", &consumer_output.data))
        .expect("failed to load consumer")
        .relocator()
        .scope([host_symbols.source("__host")])
        .relocate()
        .expect("failed to relocate consumer");

    assert_eq!(
        got_slot_word(&relocated, &consumer_output, EXTERNAL_VAR_NAME),
        host_symbols.addresses[EXTERNAL_VAR_NAME] as u64
    );
    assert!(
        relocated.deps().is_empty(),
        "synthetic modules should not appear as loaded dependencies"
    );
}

#[test]
fn extend_scope_keeps_existing_precedence() {
    let mut loader = Loader::new();
    let first_output = write_helper_dylib(SHARED_VAR_NAME, &[0x11, 0x22, 0x33, 0x44]);
    let second_output = write_helper_dylib(SHARED_VAR_NAME, &[0x55, 0x66, 0x77, 0x88]);
    let first = load_relocated_dylib(&mut loader, "libfirst.so", &first_output);
    let second = load_relocated_dylib(&mut loader, "libsecond.so", &second_output);
    let consumer_output = write_got_consumer(SHARED_VAR_NAME);

    let relocated = loader
        .load_dylib(ElfBinary::new("consumer.so", &consumer_output.data))
        .expect("failed to load consumer")
        .relocator()
        .scope(&[first.clone()])
        .extend_scope(&[second.clone()])
        .relocate()
        .expect("failed to relocate consumer");

    assert_eq!(
        got_slot_word(&relocated, &consumer_output, SHARED_VAR_NAME),
        symbol_address(&first, SHARED_VAR_NAME)
    );
    let deps = relocated.deps().collect::<Vec<_>>();
    assert_eq!(
        deps.len(),
        2,
        "all scope entries should be retained as dependencies"
    );
    assert_eq!(deps[0].name(), first.name());
    assert_eq!(deps[1].name(), second.name());
}
