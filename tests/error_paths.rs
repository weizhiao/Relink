mod support;

use elf_loader::{Loader, input::ElfBinary};
use gen_elf::{Arch, RelocEntry, SymbolDesc};
use support::test_dylib::write_test_dylib;

#[test]
fn missing_path_fails() {
    let mut loader = Loader::new();
    let _error = loader
        .load_dylib("target/this_location_is_definitely_non existent:^~")
        .expect_err("loading a missing path should fail");
}

#[test]
fn unresolved_symbol_fails_bind_now_relocation() {
    let arch = Arch::current();
    let output = write_test_dylib(
        &[RelocEntry::jump_slot("missing_func", arch)],
        &[SymbolDesc::undefined_func("missing_func")],
    );

    let error = Loader::new()
        .load_dylib(ElfBinary::new("missing.so", &output.data))
        .expect("failed to load unresolved ELF")
        .relocator()
        .relocate()
        .expect_err("bind-now relocation should fail for an unresolved symbol");

    let message = error.to_string();
    assert!(
        message.contains("missing_func"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("Relocation error"),
        "unexpected error: {message}"
    );
}

#[cfg(not(feature = "tls"))]
#[test]
fn tls_image_requires_feature() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_tls("tls_value", &[1, 2, 3, 4])]);

    let error = Loader::new()
        .load_dylib(ElfBinary::new("tls_disabled.so", &output.data))
        .expect_err("TLS image should fail to load without the `tls` feature");

    let message = error.to_string();
    assert!(
        message.contains("TLS support is not compiled into this build"),
        "unexpected error: {message}"
    );
}

#[cfg(feature = "tls")]
#[test]
fn tls_image_requires_resolver() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_tls("tls_value", &[1, 2, 3, 4])]);

    let error = Loader::new()
        .load_dylib(ElfBinary::new("tls_requires_resolver.so", &output.data))
        .expect_err("TLS image should fail to load without a TLS resolver");

    let message = error.to_string();
    assert!(
        message.contains("with_default_tls_resolver()"),
        "unexpected error: {message}"
    );
}
