use elf_loader::{Loader, elf::ElfProgramType, image::ScannedElf, input::ElfBinary};

const LOADER: Loader = Loader::new();

#[test]
fn dynamic_reuses_mapping() {
    let bytes = crate::fixture::fixtures().dylib.clone();

    let owner = LOADER
        .run(elf_loader::Domain::native(
            elf_loader::AddressSpaceId::PROCESS,
        ))
        .load_dylib(ElfBinary::new("owner.so", &bytes))
        .expect("failed to map owner dylib");
    let base = owner.segments().base();

    let borrowed = unsafe {
        LOADER
            .run(elf_loader::Domain::native(
                elf_loader::AddressSpaceId::PROCESS,
            ))
            .load_mapped_dynamic("borrowed-main", base, owner.phdrs().to_vec(), owner.entry())
    }
    .expect("failed to wrap borrowed mapping");

    assert_eq!(borrowed.path().as_bytes(), b"borrowed-main");
    assert_eq!(borrowed.name(), b"borrowed-main");
    assert_eq!(borrowed.segments().base(), base);
    assert_eq!(borrowed.entry(), owner.entry());
    assert!(borrowed.segments().contains_addr(base));
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
    let mut run = LOADER.run(elf_loader::Domain::native(
        elf_loader::AddressSpaceId::PROCESS,
    ));
    let bytes = crate::fixture::fixtures().dylib.clone();

    let ScannedElf::Dynamic(scanned) = run
        .scan(ElfBinary::owned("scanned.so", bytes))
        .expect("failed to scan dylib")
    else {
        panic!("compiled dylib should scan as dynamic");
    };
    let soname = scanned.soname().map(<[u8]>::to_vec);

    let raw = run
        .load_scanned_dynamic(scanned)
        .expect("failed to load scanned dynamic image");

    assert_eq!(raw.path().as_bytes(), b"scanned.so");
    assert_eq!(raw.soname(), soname.as_deref());
    assert_eq!(raw.name(), b"scanned.so");
    assert!(
        raw.phdrs()
            .iter()
            .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
    );
}
