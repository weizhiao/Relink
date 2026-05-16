mod support;

use elf_loader::{Loader, image::ScannedElf, input::ElfBinary};
use gen_elf::{Arch, ElfWriterConfig, SymbolDesc};
use support::{generated_dylib::return_42_stub, test_dylib::write_test_dylib_with_config};

#[derive(Default)]
struct ScanData {
    value: usize,
}

#[test]
fn borrowed_dynamic_reuses_existing_mapping() {
    let arch = Arch::current();
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_soname("libowner.so"),
        &[],
        &[SymbolDesc::global_func("answer", &return_42_stub(arch))],
    );

    let mut owner_loader = Loader::new();
    let owner = owner_loader
        .load_dylib(ElfBinary::new("owner.so", &output.data))
        .expect("failed to map owner dylib");
    let owner_dynamic = owner.dynamic_ptr().expect("owner should have PT_DYNAMIC");

    let mut borrowed_loader = Loader::new();
    let borrowed = unsafe {
        borrowed_loader.load_mapped_dynamic(
            "borrowed-main",
            owner.base(),
            owner.phdrs().to_vec(),
            owner.entry(),
        )
    }
    .expect("failed to wrap borrowed mapping");

    assert_eq!(borrowed.path().as_str(), "borrowed-main");
    assert_eq!(borrowed.name(), "libowner.so");
    assert_eq!(borrowed.base(), owner.base());
    assert_eq!(borrowed.entry(), owner.entry());
    assert_eq!(borrowed.mapped_len(), owner.mapped_len());
    assert!(borrowed.contains_addr(owner.base()));
    assert_eq!(borrowed.dynamic_ptr(), Some(owner_dynamic));
    assert_eq!(borrowed.needed_libs(), owner.needed_libs());
    assert_eq!(owner.soname(), Some("libowner.so"));
    assert_eq!(borrowed.soname(), owner.soname());
}

#[test]
fn scanned_dynamic_load_reuses_scanned_metadata() {
    let arch = Arch::current();
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_soname("libscanned.so"),
        &[],
        &[SymbolDesc::global_func("answer", &return_42_stub(arch))],
    );
    let bytes = output.data;

    let mut loader = Loader::new().with_dynamic_initializer::<ScanData>(|dynamic| {
        if let Some(data) = dynamic.user_data_mut() {
            data.value = 42;
        }
        Ok(())
    });
    let ScannedElf::Dynamic(scanned) = loader
        .scan(ElfBinary::owned("scanned.so", bytes))
        .expect("failed to scan dylib")
    else {
        panic!("generated dylib should scan as dynamic");
    };
    assert_eq!(scanned.soname(), Some("libscanned.so"));

    let raw = loader
        .load_scanned_dynamic(scanned)
        .expect("failed to load scanned dynamic image");

    assert_eq!(raw.path().as_str(), "scanned.so");
    assert_eq!(raw.name(), "libscanned.so");
    assert_eq!(raw.soname(), Some("libscanned.so"));
    assert_eq!(raw.user_data().value, 42);
    assert!(raw.dynamic_ptr().is_some());
}
