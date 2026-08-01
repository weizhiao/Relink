use elf_loader::{Module, Relocator};

#[test]
fn exports_survive_init_symtab() {
    use elf_loader::{
        Loader, Result,
        elf::{ElfSectionId, ElfSectionType},
        input::ElfBinary,
        observer::{
            LoadObserver, SectionGroup, SectionGroups, SectionLayoutEvent, SectionLifetime,
        },
        os::ProtFlags,
    };

    struct InitSymtabObserver {
        init_meta: SectionGroup,
    }

    impl LoadObserver for InitSymtabObserver {
        fn on_section_layout(&mut self, event: &mut SectionLayoutEvent<'_>) -> Result<()> {
            let ids = event.section_ids().collect::<Vec<_>>();
            for id in ids {
                if event.sections().section(id).section_type() != ElfSectionType::SYMTAB {
                    continue;
                }

                event.place(id, self.init_meta);
                event.place(
                    ElfSectionId::new(event.sections().section(id).sh_link() as usize),
                    self.init_meta,
                );
            }

            Ok(())
        }
    }

    let fixtures = crate::fixture::fixtures();
    let provider = Relocator::new()
        .run(
            Loader::new()
                .load_dylib(ElfBinary::new("provider.so", &fixtures.provider))
                .expect("failed to load object dependency"),
        )
        .relocate()
        .expect("failed to relocate object dependency");
    let mut groups = SectionGroups::default();
    let init_meta = groups.define(
        ProtFlags::PROT_READ,
        ProtFlags::PROT_READ,
        10,
        SectionLifetime::Init,
    );

    let loaded_object = Relocator::new()
        .run(
            elf_loader::Loader::new()
                .run()
                .with_object_section_groups(groups)
                .with_observer(InitSymtabObserver { init_meta })
                .load_object(ElfBinary::new("dependent.o", &fixtures.dependent_object))
                .expect("failed to load object"),
        )
        .scope([&provider])
        .relocate()
        .expect("relocation failed");

    assert!(loaded_object.state().is_initialized());
    assert!(
        unsafe {
            loaded_object
                .get::<extern "C" fn() -> i32>("dependent_value")
                .is_some()
        },
        "runtime object exports should survive init metadata release"
    );
}

#[test]
fn exposes_sections() {
    use elf_loader::{
        Result,
        arch::NativeArch,
        image::{LoadedCore, ModuleHandle},
        memory::{HostRegion, RegionAccess},
        observer::{LoadObserver, ObjectRelocatedEvent, RelocationObserver, SectionLayoutEvent},
        tls::TlsResolver,
    };

    struct SkipComment;

    impl LoadObserver for SkipComment {
        fn on_section_layout(&mut self, event: &mut SectionLayoutEvent<'_>) -> Result<()> {
            let comment = event
                .sections()
                .find_section(".comment")
                .expect("compiled object should contain .comment");
            event.skip(comment);
            Ok(())
        }
    }

    struct MetadataObserver;

    impl RelocationObserver for MetadataObserver {
        fn on_object_relocated<
            D: Send + Sync + 'static,
            R: RegionAccess,
            Tls: TlsResolver<NativeArch>,
        >(
            &mut self,
            event: &mut ObjectRelocatedEvent<'_, D, NativeArch, R, Tls>,
        ) -> Result<()> {
            let data = event
                .sections()
                .find_section(".data.value")
                .expect("compiled object should contain .data.value");
            assert!(event.section_is_mapped(data));
            assert!(event.section_addr(data).is_some());
            assert!(event.section_host_ptr(data).is_some());
            assert_eq!(
                event.sections().section_name(data).to_bytes(),
                b".data.value"
            );

            let symtab = event
                .sections()
                .find_section(".symtab")
                .expect("generated object should contain .symtab");
            assert!(event.section_is_mapped(symtab));

            let comment = event
                .sections()
                .find_section(".comment")
                .expect("compiled object should contain .comment");
            assert!(!event.section_is_mapped(comment));
            assert!(event.section_addr(comment).is_none());
            assert!(event.section_host_ptr(comment).is_none());
            assert!(event.section_host_ptr_range(comment, 1).is_none());
            Ok(())
        }
    }

    let object = &crate::fixture::fixtures().provider_object;

    let loaded_object = Relocator::new()
        .run(
            elf_loader::Loader::new()
                .run()
                .with_observer(SkipComment)
                .load_object(elf_loader::input::ElfBinary::new("a.o", object))
                .expect("failed to load object"),
        )
        .observer(MetadataObserver)
        .relocate()
        .expect("relocation failed");

    let handle: ModuleHandle = (&loaded_object).into();
    handle
        .downcast_ref::<LoadedCore<(), NativeArch, HostRegion>>()
        .expect("ModuleHandle should retain loaded core");
}

#[test]
fn can_clear_exports() {
    use elf_loader::{
        Result,
        arch::NativeArch,
        memory::{ImageMemory, RegionAccess, VmOffset},
        observer::{ObjectRelocatedEvent, RelocationObserver},
        tls::TlsResolver,
    };
    const VALUE: &str = "value";

    struct ClearExports;

    impl RelocationObserver for ClearExports {
        fn on_object_relocated<
            D: Send + Sync + 'static,
            R: RegionAccess,
            Tls: TlsResolver<NativeArch>,
        >(
            &mut self,
            event: &mut ObjectRelocatedEvent<'_, D, NativeArch, R, Tls>,
        ) -> Result<()> {
            let symtab = event.symtab();
            assert!(
                (0..symtab.symbols().len()).any(|idx| symtab.symbol_idx(idx).name() == VALUE),
                "relocated object symbol table should include the global object symbol"
            );
            let symbol = (0..symtab.symbols().len())
                .map(|idx| symtab.symbol_idx(idx))
                .find(|entry| entry.name() == VALUE)
                .expect("value symbol should exist");
            let addr = event.core().base() + VmOffset::new(symbol.symbol().st_value());
            let mut bytes = [0u8; 4];
            event.memory().read_bytes(addr, &mut bytes)?;
            assert_eq!(bytes, [1, 2, 3, 4]);
            event.clear_exports();
            Ok(())
        }
    }

    let object = &crate::fixture::fixtures().provider_object;

    let loaded_object = Relocator::new()
        .run(
            elf_loader::Loader::new()
                .load_object(elf_loader::input::ElfBinary::new("a.o", object))
                .expect("failed to load object"),
        )
        .observer(ClearExports)
        .relocate()
        .expect("relocation failed");

    assert!(
        unsafe { loaded_object.get::<i32>(VALUE) }.is_none(),
        "object export event should be able to replace the default exports"
    );
}
