use elf_loader::{Error, Loader, Relocator, error::RelocationError, input::ElfBinary};
use gen_elf::{Arch, DylibWriter, ElfWriterConfig, RelocEntry, SymbolDesc};

#[test]
fn unresolved_symbol_fails_bind_now() {
    let arch = Arch::current();
    let output = DylibWriter::with_config(arch, ElfWriterConfig::default().with_bind_now(true))
        .write(
            &[RelocEntry::jump_slot("missing_func", arch)],
            &[SymbolDesc::undefined_func("missing_func")],
        )
        .expect("failed to generate unresolved dylib");

    let error = Relocator::new()
        .run(
            Loader::new()
                .load_dylib(ElfBinary::new("missing.so", &output.data))
                .expect("failed to load unresolved ELF"),
        )
        .relocate()
        .expect_err("bind-now relocation should fail for an unresolved symbol");

    let message = error.to_string();
    assert!(matches!(
        error,
        Error::Relocation(RelocationError::Context(_))
    ));
    assert!(
        message.contains("missing_func"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("Relocation error"),
        "unexpected error: {message}"
    );
}
