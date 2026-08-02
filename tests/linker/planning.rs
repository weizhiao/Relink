use super::*;
use std::sync::OnceLock;

#[cfg(target_pointer_width = "64")]
const E_SHOFF_OFFSET: usize = 0x28;
#[cfg(not(target_pointer_width = "64"))]
const E_SHOFF_OFFSET: usize = 0x20;
#[cfg(target_pointer_width = "64")]
const E_SHNUM_OFFSET: usize = 0x3c;
#[cfg(not(target_pointer_width = "64"))]
const E_SHNUM_OFFSET: usize = 0x30;
#[cfg(target_pointer_width = "64")]
const E_SHSTRNDX_OFFSET: usize = 0x3e;
#[cfg(not(target_pointer_width = "64"))]
const E_SHSTRNDX_OFFSET: usize = 0x32;

struct PlanningFixtures {
    basic: &'static [u8],
    missing_sections: Vec<u8>,
    invalid_sections: Vec<u8>,
    #[cfg(target_arch = "x86_64")]
    retained: &'static [u8],
}

fn fixtures() -> &'static PlanningFixtures {
    static FIXTURES: OnceLock<PlanningFixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let real = crate::fixture::fixtures();
        PlanningFixtures {
            basic: &real.plain,
            missing_sections: strip_section_headers(real.plain.clone()),
            invalid_sections: break_section_name_table(real.plain.clone()),
            #[cfg(target_arch = "x86_64")]
            retained: &real.provider,
        }
    })
}

fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[cfg(target_pointer_width = "64")]
fn set_usize(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 8].copy_from_slice(&(value as u64).to_le_bytes());
}

#[cfg(not(target_pointer_width = "64"))]
fn set_usize(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
}

fn strip_section_headers(mut bytes: Vec<u8>) -> Vec<u8> {
    set_usize(&mut bytes, E_SHOFF_OFFSET, 0);
    set_u16(&mut bytes, E_SHNUM_OFFSET, 0);
    set_u16(&mut bytes, E_SHSTRNDX_OFFSET, 0);
    bytes
}

fn break_section_name_table(mut bytes: Vec<u8>) -> Vec<u8> {
    set_u16(&mut bytes, E_SHSTRNDX_OFFSET, u16::MAX);
    bytes
}

#[test]
#[cfg(target_arch = "x86_64")]
fn arena_materializes_section_bytes() {
    let bytes = fixtures().retained;

    let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "arena_root.so",
        data: bytes,
    };
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, ReorderPass>| -> elf_loader::Result<()> {
            let root = plan.root().expect("root module should be visible");
            assert!(
                root.capability(plan) == ModuleCapability::SectionReorderable,
                "compiled dylib should expose retained relocation repair inputs",
            );

            let data_section = root
                .scanned(plan)
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("compiled dylib should contain a .data section")
                .id();
            let layout_section = root
                .section(plan, data_section)
                .expect("missing planned .data section");
            {
                layout_section
                    .data_mut(plan)?
                    .copy_from_slice(&[9, 8, 7, 6]);
                let arena = plan.create_arena(ArenaDescriptor::new(
                    PageSize::Base,
                    MemoryClass::WritableData,
                    ArenaSharing::Private,
                ));
                assert!(
                    layout_section.assign(plan, arena, 0),
                    "failed to assign .data into arena",
                );
            }
            Ok(())
        };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to execute arena-backed scan-first load");

    assert!(
        !loaded.segments().is_contiguous_mapping(),
        "arena-backed load should expose a sparse mapped span",
    );
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn arena_supports_assign_next() {
    let bytes = fixtures().retained;

    let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "arena_assign_next_root.so",
        data: bytes,
    };
    let mut observed_offset = None;
    let mut observed_size = None;
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, ReorderPass>| -> elf_loader::Result<()> {
            let root = plan.root().expect("root module should be visible");
            assert!(
                root.capability(plan) == ModuleCapability::SectionReorderable,
                "compiled dylib should expose retained relocation repair inputs",
            );

            let data_section = root
                .scanned(plan)
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("compiled dylib should contain a .data section")
                .id();
            let layout_section = root
                .section(plan, data_section)
                .expect("missing planned .data section");
            layout_section.resize(plan, 8)?;
            assert_eq!(layout_section.metadata(plan).size(), 8);
            layout_section
                .data_mut(plan)?
                .copy_from_slice(&[4, 3, 2, 1, 8, 7, 6, 5]);

            let arena = plan.create_arena(ArenaDescriptor::new(
                PageSize::Base,
                MemoryClass::WritableData,
                ArenaSharing::Private,
            ));
            assert!(
                layout_section.assign_next(plan, arena),
                "failed to assign .data into arena at the next aligned offset",
            );
            observed_offset = layout_section
                .placement(plan)
                .map(|placement| placement.offset());
            observed_size = layout_section
                .placement(plan)
                .map(|placement| placement.size());
            Ok(())
        };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to execute arena-backed scan-first load with assign_next");

    assert_eq!(observed_offset, Some(0));
    assert_eq!(observed_size, Some(8));
    assert!(
        !loaded.segments().is_contiguous_mapping(),
        "arena-backed load should expose a sparse mapped span",
    );
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[4, 3, 2, 1]);
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn defaults_to_section_regions() {
    let bytes = fixtures().retained;

    let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "default_section_regions_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let configure = |plan: &mut LinkPassPlan<'_, &'static str>| -> elf_loader::Result<()> {
        let root = plan.root().expect("root module should be visible");
        observed_capability = Some(root.capability(plan));
        Ok(())
    };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to load section-reorderable dylib through the default section-region path");

    assert_eq!(
        observed_capability,
        Some(ModuleCapability::SectionReorderable),
    );
    assert!(
        !loaded.segments().is_contiguous_mapping(),
        "section-region default should materialize alloc sections into mapped arenas",
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn missing_sections_become_opaque() {
    let bytes = fixtures().missing_sections.as_slice();

    let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "opaque_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let mut saw_missing_section_headers = false;
    let configure = |plan: &mut LinkPassPlan<'_, &'static str>| -> elf_loader::Result<()> {
        let root = plan.root().expect("root module should be visible");
        observed_capability = Some(root.capability(plan));
        saw_missing_section_headers = root.scanned(plan).section_headers().is_none();
        root.set_materialization(plan, Materialization::WholeDsoRegion);
        Ok(())
    };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to load opaque dylib through scan-first path");

    assert_eq!(observed_capability, Some(ModuleCapability::Opaque));
    assert!(
        saw_missing_section_headers,
        "opaque modules should not expose a usable section table",
    );

    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn invalid_sections_become_opaque() {
    let bytes = fixtures().invalid_sections.as_slice();

    let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "broken_shstr_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let configure = |plan: &mut LinkPassPlan<'_, &'static str>| -> elf_loader::Result<()> {
        let root = plan.root().expect("root module should be visible");
        observed_capability = Some(root.capability(plan));
        Ok(())
    };

    let _loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("scan-first load should downgrade unusable section tables");

    assert_eq!(observed_capability, Some(ModuleCapability::Opaque));
}

#[test]
fn whole_dso_supports_section_overrides() {
    let bytes = fixtures().basic;

    let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "whole_region_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let mut observed_materialization = None;
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, DataPass>| -> elf_loader::Result<()> {
            let root = plan.root().expect("root module should be visible");
            observed_capability = Some(root.capability(plan));
            observed_materialization = root.materialization(plan);

            let data_section = root
                .scanned(plan)
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("compiled dylib should contain a .data section")
                .id();
            let layout_section = root
                .section(plan, data_section)
                .expect("missing planned .data section");
            layout_section
                .data_mut(plan)?
                .copy_from_slice(&[9, 8, 7, 6]);
            root.set_materialization(plan, Materialization::WholeDsoRegion);
            observed_materialization = root.materialization(plan);
            Ok(())
        };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to execute whole-DSO scan-first load");

    assert_eq!(
        observed_capability,
        Some(ModuleCapability::SectionData),
        "no emit-relocs should classify as section-data only",
    );
    assert_eq!(
        observed_materialization,
        Some(Materialization::WholeDsoRegion),
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
fn section_data_rejects_section_regions() {
    let bytes = fixtures().basic;

    let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "illegal_section_region_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let mut observed_materialization = None;
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, DataPass>| -> elf_loader::Result<()> {
            let root = plan.root().expect("root module should be visible");
            observed_capability = Some(root.capability(plan));

            assert_eq!(
                root.set_materialization(plan, Materialization::SectionRegions),
                None,
            );
            observed_materialization = root.materialization(plan);
            Ok(())
        };

    let err = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect_err("section-data modules must reject section-region placement");
    assert_eq!(observed_capability, Some(ModuleCapability::SectionData));
    assert_eq!(
        observed_materialization,
        Some(Materialization::SectionRegions)
    );
    assert!(
        err.to_string().contains("cannot use section regions"),
        "unexpected error: {err}",
    );
}
