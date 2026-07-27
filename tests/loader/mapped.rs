use elf_loader::{Loader, elf::ElfProgramType, image::ScannedElf, input::ElfBinary};

const LOADER: Loader = Loader::new();

#[test]
fn dynamic_reuses_mapping() {
    let bytes = crate::fixture::fixtures().dylib.clone();

    let owner = LOADER
        .load_dylib(ElfBinary::new("owner.so", &bytes))
        .expect("failed to map owner dylib");

    let borrowed = unsafe {
        LOADER.load_mapped_dynamic(
            "borrowed-main",
            owner.base(),
            owner.phdrs().to_vec(),
            owner.entry(),
        )
    }
    .expect("failed to wrap borrowed mapping");

    assert_eq!(borrowed.path().as_str(), "borrowed-main");
    assert_eq!(
        borrowed.name(),
        owner.soname().unwrap_or("borrowed-main"),
        "module names should prefer DT_SONAME and otherwise use their own path",
    );
    assert_eq!(borrowed.base(), owner.base());
    assert_eq!(borrowed.entry(), owner.entry());
    assert!(borrowed.segments().contains_addr(owner.base()));
    assert_eq!(borrowed.phdrs().len(), owner.phdrs().len());
    assert!(
        borrowed
            .phdrs()
            .iter()
            .zip(owner.phdrs())
            .all(
                |(borrowed, owner)| borrowed.program_type() == owner.program_type()
                    && borrowed.p_vaddr() == owner.p_vaddr()
                    && borrowed.p_memsz() == owner.p_memsz()
            )
    );
    assert_eq!(borrowed.needed_libs(), owner.needed_libs());
    assert_eq!(borrowed.soname(), owner.soname());
}

#[test]
fn scanned_dynamic_reuses_metadata() {
    let bytes = crate::fixture::fixtures().dylib.clone();

    let ScannedElf::Dynamic(scanned) = LOADER
        .scan(ElfBinary::owned("scanned.so", bytes))
        .expect("failed to scan dylib")
    else {
        panic!("compiled dylib should scan as dynamic");
    };
    let soname = scanned.soname().map(str::to_owned);

    let raw = LOADER
        .load_scanned_dynamic(scanned)
        .expect("failed to load scanned dynamic image");

    assert_eq!(raw.path().as_str(), "scanned.so");
    assert_eq!(raw.soname(), soname.as_deref());
    assert_eq!(raw.name(), soname.as_deref().unwrap_or("scanned.so"));
    assert!(
        raw.phdrs()
            .iter()
            .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
    );
}
