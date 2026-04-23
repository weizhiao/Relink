mod support;

use elf_loader::{
    image::{LoadedCore, ModuleCapability},
    input::ElfBinary,
    linker::{Arena, ArenaSharing, MemoryClass},
    linker::{
        DataPass, KeyResolver, LinkContext, LinkPassPlan, Linker, Materialization,
        RelocationInputs, RelocationRequest, ReorderPass, ResolvedKey,
    },
};
use gen_elf::{ElfWriterConfig, SymbolDesc};
use std::{boxed::Box, vec::Vec};
use support::test_dylib::{write_test_dylib, write_test_dylib_with_config};

struct SingleBinaryResolver {
    key: &'static str,
    name: &'static str,
    data: &'static [u8],
}

struct ExistingRootResolver {
    requested: &'static str,
    existing: &'static str,
}

impl KeyResolver<'static, &'static str, ()> for SingleBinaryResolver {
    fn load_root(
        &mut self,
        key: &&'static str,
    ) -> elf_loader::Result<ResolvedKey<'static, &'static str>> {
        assert_eq!(*key, self.key);
        Ok(ResolvedKey::load(
            self.key,
            ElfBinary::new(self.name, self.data),
        ))
    }

    fn resolve_dependency(
        &mut self,
        _req: &elf_loader::linker::DependencyRequest<'_, &'static str, ()>,
    ) -> elf_loader::Result<Option<ResolvedKey<'static, &'static str>>> {
        Ok(None)
    }
}

impl KeyResolver<'static, &'static str, ()> for ExistingRootResolver {
    fn load_root(
        &mut self,
        key: &&'static str,
    ) -> elf_loader::Result<ResolvedKey<'static, &'static str>> {
        assert_eq!(*key, self.requested);
        Ok(ResolvedKey::existing(self.existing))
    }

    fn resolve_dependency(
        &mut self,
        _req: &elf_loader::linker::DependencyRequest<'_, &'static str, ()>,
    ) -> elf_loader::Result<Option<ResolvedKey<'static, &'static str>>> {
        panic!("existing scan root should not resolve dependencies")
    }
}

#[cfg(target_pointer_width = "64")]
const E_SHOFF_OFFSET: usize = 0x28;
#[cfg(target_pointer_width = "64")]
const E_SHNUM_OFFSET: usize = 0x3c;
#[cfg(target_pointer_width = "64")]
const E_SHSTRNDX_OFFSET: usize = 0x3e;

#[cfg(not(target_pointer_width = "64"))]
const E_SHOFF_OFFSET: usize = 0x20;
#[cfg(not(target_pointer_width = "64"))]
const E_SHNUM_OFFSET: usize = 0x30;
#[cfg(not(target_pointer_width = "64"))]
const E_SHSTRNDX_OFFSET: usize = 0x32;

fn set_ehdr_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[cfg(target_pointer_width = "64")]
fn set_ehdr_usize(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 8].copy_from_slice(&(value as u64).to_le_bytes());
}

#[cfg(not(target_pointer_width = "64"))]
fn set_ehdr_usize(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
}

fn strip_section_headers(mut bytes: Vec<u8>) -> Vec<u8> {
    set_ehdr_usize(&mut bytes, E_SHOFF_OFFSET, 0);
    set_ehdr_u16(&mut bytes, E_SHNUM_OFFSET, 0);
    set_ehdr_u16(&mut bytes, E_SHSTRNDX_OFFSET, 0);
    bytes
}

fn break_section_name_table(mut bytes: Vec<u8>) -> Vec<u8> {
    set_ehdr_u16(&mut bytes, E_SHSTRNDX_OFFSET, u16::MAX);
    bytes
}

fn empty_relocation_plan(
    _req: &RelocationRequest<'_, &'static str, ()>,
) -> Result<RelocationInputs<()>, elf_loader::Error> {
    Ok(RelocationInputs::new(Vec::<LoadedCore<()>>::new()))
}

#[test]
fn load_with_scan_legacy_path_applies_section_overrides_and_exposes_mapped_span() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "planned_root.so",
        data: bytes,
    };
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, (), DataPass>| -> elf_loader::Result<()> {
            let root = plan.root();
            let data_section = plan
                .get(root)
                .expect("missing scanned root module")
                .module()
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = plan
                .section(root, data_section)
                .expect("missing planned .data section");
            plan.data_mut(layout_section)?
                .expect("missing materialized .data bytes")
                .as_bytes_mut()
                .copy_from_slice(&[9, 8, 7, 6]);
            Ok(())
        };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(configure);
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute scan-first load");

    assert!(loaded.is_contiguous_mapping());
    assert!(loaded.mapped_len() > 0);
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
fn load_with_scan_legacy_path_loads_without_an_intermediate_plan() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "merged_root.so",
        data: bytes,
    };
    let loaded = Linker::new()
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute merged scan-and-load path");

    assert!(loaded.is_contiguous_mapping());
    assert!(loaded.mapped_len() > 0);
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn load_with_scan_reuses_existing_root_alias_without_planning() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[5, 6, 7, 8])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();

    let load_resolver = SingleBinaryResolver {
        key: "canonical",
        name: "canonical.so",
        data: bytes,
    };
    let loaded = Linker::new()
        .resolver(load_resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "canonical")
        .expect("failed to load canonical scan root");

    let alias_resolver = ExistingRootResolver {
        requested: "alias",
        existing: "canonical",
    };
    let alias_loaded = Linker::new()
        .resolver(alias_resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "alias")
        .expect("failed to reuse existing scan root");

    assert_eq!(alias_loaded.base(), loaded.base());
    assert_eq!(alias_loaded.mapped_len(), loaded.mapped_len());
    assert!(context.contains_key(&"canonical"));
    assert!(!context.contains_key(&"alias"));
}

#[test]
fn load_with_scan_arena_backed_path_materializes_section_bytes_into_runtime_memory() {
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_emit_retained_relocations(true),
        &[],
        &[SymbolDesc::global_object("value", &[1, 2, 3, 4])],
    );
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "arena_root.so",
        data: bytes,
    };
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, (), ReorderPass>| -> elf_loader::Result<()> {
            let root = plan.root();
            assert!(
                plan.capability(root) == Some(ModuleCapability::SectionReorderable),
                "generated test dylib should expose retained relocation repair inputs",
            );

            let data_section = plan
                .get(root)
                .expect("missing scanned root module")
                .module()
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = plan
                .section(root, data_section)
                .expect("missing planned .data section");
            {
                plan.data_mut(layout_section)?
                    .expect("missing materialized .data bytes")
                    .as_bytes_mut()
                    .copy_from_slice(&[9, 8, 7, 6]);
                let arena = plan.create_arena(Arena::new(
                    4096,
                    MemoryClass::WritableData,
                    ArenaSharing::Private,
                ));
                assert!(
                    plan.assign(layout_section, arena, 0),
                    "failed to assign .data into arena",
                );
            }
            Ok(())
        };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(configure);
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute arena-backed scan-first load");

    assert!(
        !loaded.is_contiguous_mapping(),
        "arena-backed load should expose a sparse mapped span",
    );
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
fn load_with_scan_arena_backed_path_supports_assign_next() {
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_emit_retained_relocations(true),
        &[],
        &[SymbolDesc::global_object("value", &[1, 2, 3, 4])],
    );
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "arena_assign_next_root.so",
        data: bytes,
    };
    let mut observed_offset = None;
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, (), ReorderPass>| -> elf_loader::Result<()> {
            let root = plan.root();
            assert!(
                plan.capability(root) == Some(ModuleCapability::SectionReorderable),
                "generated test dylib should expose retained relocation repair inputs",
            );

            let data_section = plan
                .get(root)
                .expect("missing scanned root module")
                .module()
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = plan
                .section(root, data_section)
                .expect("missing planned .data section");
            plan.data_mut(layout_section)?
                .expect("missing materialized .data bytes")
                .as_bytes_mut()
                .copy_from_slice(&[4, 3, 2, 1]);

            let arena = plan.create_arena(Arena::new(
                4096,
                MemoryClass::WritableData,
                ArenaSharing::Private,
            ));
            assert!(
                plan.assign_next(layout_section, arena),
                "failed to assign .data into arena at the next aligned offset",
            );
            observed_offset = plan
                .placement(layout_section)
                .map(|placement| placement.offset());
            Ok(())
        };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(configure);
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute arena-backed scan-first load with assign_next");

    assert_eq!(observed_offset, Some(0));
    assert!(
        !loaded.is_contiguous_mapping(),
        "arena-backed load should expose a sparse mapped span",
    );
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[4, 3, 2, 1]);
    }
}

#[test]
fn load_with_scan_defaults_section_reorderable_modules_to_section_regions() {
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_emit_retained_relocations(true),
        &[],
        &[SymbolDesc::global_object("value", &[1, 2, 3, 4])],
    );
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "default_section_regions_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        let root = plan.root();
        observed_capability = plan.capability(root);
        Ok(())
    };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(configure);
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to load section-reorderable dylib through the default section-region path");

    assert_eq!(
        observed_capability,
        Some(ModuleCapability::SectionReorderable),
    );
    assert!(
        !loaded.is_contiguous_mapping(),
        "section-region default should materialize alloc sections into mapped arenas",
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn load_with_scan_handles_missing_section_headers_as_opaque_module() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(strip_section_headers(output.data).into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "opaque_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let mut saw_missing_section_headers = false;
    let configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        let root = plan.root();
        observed_capability = plan.capability(root);
        saw_missing_section_headers = plan
            .get(root)
            .and_then(|module| module.module().section_headers())
            .is_none();
        plan.set_materialization(root, Materialization::WholeDsoRegion);
        Ok(())
    };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(configure);
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to load opaque dylib through scan-first path");

    assert_eq!(observed_capability, Some(ModuleCapability::Opaque));
    assert!(
        saw_missing_section_headers,
        "opaque modules should not expose a usable section table",
    );

    assert!(loaded.mapped_len() > 0);
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn load_with_scan_downgrades_unusable_section_table_to_opaque() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(break_section_name_table(output.data).into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "broken_shstr_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        let root = plan.root();
        observed_capability = plan.capability(root);
        Ok(())
    };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(configure);
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("scan-first load should downgrade unusable section tables");

    assert!(loaded.mapped_len() > 0);
    assert_eq!(observed_capability, Some(ModuleCapability::Opaque));
}

#[test]
fn load_with_scan_supports_whole_dso_regions_and_section_overrides_for_section_data_modules() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "whole_region_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let mut observed_materialization = None;
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, (), DataPass>| -> elf_loader::Result<()> {
            let root = plan.root();
            observed_capability = plan.capability(root);
            observed_materialization = plan.materialization(root);

            let data_section = plan
                .get(root)
                .expect("missing scanned root module")
                .module()
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = plan
                .section(root, data_section)
                .expect("missing planned .data section");
            plan.data_mut(layout_section)?
                .expect("missing materialized .data bytes")
                .as_bytes_mut()
                .copy_from_slice(&[9, 8, 7, 6]);
            plan.set_materialization(root, Materialization::WholeDsoRegion);
            observed_materialization = plan.materialization(root);
            Ok(())
        };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(configure);
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
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

    assert!(
        loaded.mapped_len() > 0,
        "whole-DSO materialization should expose at least one mapped area",
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
fn load_with_scan_rejects_section_regions_for_section_data_modules() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "illegal_section_region_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let mut observed_materialization = None;
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, (), DataPass>| -> elf_loader::Result<()> {
            let root = plan.root();
            observed_capability = plan.capability(root);

            assert_eq!(
                plan.set_materialization(root, Materialization::SectionRegions),
                None,
            );
            observed_materialization = plan.materialization(root);
            Ok(())
        };

    let err = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(configure);
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
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
