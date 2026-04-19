mod support;

use elf_loader::{
    Loader,
    image::{LoadedCore, ModuleCapability},
    input::ElfBinary,
    linker::{
        KeyResolver, LinkContext, LinkPassPlan, LinkPipeline, Materialization, RelocationInputs,
        RelocationRequest, ResolvedKey,
    },
    linker::{LayoutArena, LayoutArenaSharing, LayoutMemoryClass},
    relocation::Relocator,
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
    let mut loader = Loader::new();
    let mut resolver = SingleBinaryResolver {
        key: "root",
        name: "planned_root.so",
        data: bytes,
    };
    let mut pipeline = LinkPipeline::new();
    let mut configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        let root = plan.root_module();
        let data_section = plan
            .entry(root)
            .expect("missing scanned root module")
            .alloc_sections()
            .find(|section| section.name() == ".data")
            .expect("generated test dylib should contain a .data section")
            .id();
        let layout_section = plan
            .memory_layout()
            .module_section_id(root, data_section)
            .expect("missing planned .data section");
        plan.section_data_mut(layout_section)?
            .expect("missing materialized .data bytes")
            .as_bytes_mut()
            .copy_from_slice(&[9, 8, 7, 6]);
        Ok(())
    };
    pipeline.push(&mut configure);

    let relocator = Relocator::<(), (), (), (), (), (), (), ()>::default();
    let mut planner = empty_relocation_plan;

    let loaded = context
        .load_with_scan(
            "root",
            &mut loader,
            &mut resolver,
            &mut pipeline,
            &relocator,
            &mut planner,
        )
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
    let mut loader = Loader::new();
    let mut resolver = SingleBinaryResolver {
        key: "root",
        name: "merged_root.so",
        data: bytes,
    };
    let mut pipeline = LinkPipeline::new();

    let relocator = Relocator::<(), (), (), (), (), (), (), ()>::default();
    let mut planner = empty_relocation_plan;

    let loaded = context
        .load_with_scan(
            "root",
            &mut loader,
            &mut resolver,
            &mut pipeline,
            &relocator,
            &mut planner,
        )
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
    let mut loader = Loader::new();
    let relocator = Relocator::<(), (), (), (), (), (), (), ()>::default();
    let mut planner = empty_relocation_plan;

    let mut load_resolver = SingleBinaryResolver {
        key: "canonical",
        name: "canonical.so",
        data: bytes,
    };
    let mut load_pipeline = LinkPipeline::new();
    let loaded = context
        .load_with_scan(
            "canonical",
            &mut loader,
            &mut load_resolver,
            &mut load_pipeline,
            &relocator,
            &mut planner,
        )
        .expect("failed to load canonical scan root");

    let mut alias_resolver = ExistingRootResolver {
        requested: "alias",
        existing: "canonical",
    };
    let mut alias_pipeline = LinkPipeline::new();
    let alias_loaded = context
        .load_with_scan(
            "alias",
            &mut loader,
            &mut alias_resolver,
            &mut alias_pipeline,
            &relocator,
            &mut planner,
        )
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
    let mut loader = Loader::new();
    let mut resolver = SingleBinaryResolver {
        key: "root",
        name: "arena_root.so",
        data: bytes,
    };
    let mut pipeline = LinkPipeline::new();
    let mut configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        assert!(
            plan.module_capability(&"root") == Some(ModuleCapability::SectionReorderable),
            "generated test dylib should expose retained relocation repair inputs",
        );
        let root = plan.root_module();

        let data_section = plan
            .entry(root)
            .expect("missing scanned root module")
            .alloc_sections()
            .find(|section| section.name() == ".data")
            .expect("generated test dylib should contain a .data section")
            .id();
        let layout_section = plan
            .memory_layout()
            .module_section_id(root, data_section)
            .expect("missing planned .data section");
        {
            plan.section_data_mut(layout_section)?
                .expect("missing materialized .data bytes")
                .as_bytes_mut()
                .copy_from_slice(&[9, 8, 7, 6]);
            let layout = plan.memory_layout_mut();
            let arena = layout.create_arena(LayoutArena::new(
                4096,
                LayoutMemoryClass::WritableData,
                LayoutArenaSharing::Private,
            ));
            assert!(
                layout.assign_section_to_arena(layout_section, arena, 0),
                "failed to assign .data into arena",
            );
        }
        Ok(())
    };
    pipeline.push(&mut configure);

    let relocator = Relocator::<(), (), (), (), (), (), (), ()>::default();
    let mut planner = empty_relocation_plan;

    let loaded = context
        .load_with_scan(
            "root",
            &mut loader,
            &mut resolver,
            &mut pipeline,
            &relocator,
            &mut planner,
        )
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
    let mut loader = Loader::new();
    let mut resolver = SingleBinaryResolver {
        key: "root",
        name: "default_section_regions_root.so",
        data: bytes,
    };
    let mut pipeline = LinkPipeline::new();
    let mut observed_capability = None;
    let mut observed_materialization = None;
    let mut configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        observed_capability = plan.module_capability(&"root");
        observed_materialization = plan.module_materialization(&"root");
        Ok(())
    };
    pipeline.push(&mut configure);

    let relocator = Relocator::<(), (), (), (), (), (), (), ()>::default();
    let mut planner = empty_relocation_plan;

    let loaded = context
        .load_with_scan(
            "root",
            &mut loader,
            &mut resolver,
            &mut pipeline,
            &relocator,
            &mut planner,
        )
        .expect("failed to load section-reorderable dylib through the default section-region path");

    assert_eq!(
        observed_capability,
        Some(ModuleCapability::SectionReorderable),
    );
    assert_eq!(
        observed_materialization,
        Some(Materialization::SectionRegions),
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
    let mut loader = Loader::new();
    let mut resolver = SingleBinaryResolver {
        key: "root",
        name: "opaque_root.so",
        data: bytes,
    };
    let mut pipeline = LinkPipeline::new();
    let mut observed_capability = None;
    let mut saw_missing_section_headers = false;
    let mut configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        observed_capability = plan.module_capability(&"root");
        let root = plan.root_module();
        saw_missing_section_headers = plan
            .entry(root)
            .and_then(|module| module.section_headers())
            .is_none();
        plan.set_module_materialization(root, Materialization::WholeDsoRegion);
        Ok(())
    };
    pipeline.push(&mut configure);

    let relocator = Relocator::<(), (), (), (), (), (), (), ()>::default();
    let mut planner = empty_relocation_plan;

    let loaded = context
        .load_with_scan(
            "root",
            &mut loader,
            &mut resolver,
            &mut pipeline,
            &relocator,
            &mut planner,
        )
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
    let mut loader = Loader::new();
    let mut resolver = SingleBinaryResolver {
        key: "root",
        name: "broken_shstr_root.so",
        data: bytes,
    };
    let mut pipeline = LinkPipeline::new();
    let mut observed_capability = None;
    let mut configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        observed_capability = plan.module_capability(&"root");
        Ok(())
    };
    pipeline.push(&mut configure);

    let relocator = Relocator::<(), (), (), (), (), (), (), ()>::default();
    let mut planner = empty_relocation_plan;

    let loaded = context
        .load_with_scan(
            "root",
            &mut loader,
            &mut resolver,
            &mut pipeline,
            &relocator,
            &mut planner,
        )
        .expect("scan-first load should downgrade unusable section tables");

    assert!(loaded.mapped_len() > 0);
    assert_eq!(observed_capability, Some(ModuleCapability::Opaque));
}

#[test]
fn load_with_scan_supports_whole_dso_regions_and_section_overrides_for_section_data_modules() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let mut loader = Loader::new();
    let mut resolver = SingleBinaryResolver {
        key: "root",
        name: "whole_region_root.so",
        data: bytes,
    };
    let mut pipeline = LinkPipeline::new();
    let mut observed_capability = None;
    let mut observed_materialization = None;
    let mut configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        observed_capability = plan.module_capability(&"root");
        observed_materialization = plan.module_materialization(&"root");
        let root = plan.root_module();

        let data_section = plan
            .entry(root)
            .expect("missing scanned root module")
            .alloc_sections()
            .find(|section| section.name() == ".data")
            .expect("generated test dylib should contain a .data section")
            .id();
        let layout_section = plan
            .memory_layout()
            .module_section_id(root, data_section)
            .expect("missing planned .data section");
        plan.section_data_mut(layout_section)?
            .expect("missing materialized .data bytes")
            .as_bytes_mut()
            .copy_from_slice(&[9, 8, 7, 6]);
        plan.set_module_materialization(root, Materialization::WholeDsoRegion);
        Ok(())
    };
    pipeline.push(&mut configure);

    let relocator = Relocator::<(), (), (), (), (), (), (), ()>::default();
    let mut planner = empty_relocation_plan;

    let loaded = context
        .load_with_scan(
            "root",
            &mut loader,
            &mut resolver,
            &mut pipeline,
            &relocator,
            &mut planner,
        )
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
    let mut loader = Loader::new();
    let mut resolver = SingleBinaryResolver {
        key: "root",
        name: "illegal_section_region_root.so",
        data: bytes,
    };
    let mut pipeline = LinkPipeline::new();
    let mut observed_capability = None;
    let mut configure = |plan: &mut LinkPassPlan<'_, &'static str, ()>| -> elf_loader::Result<()> {
        observed_capability = plan.module_capability(&"root");
        let root = plan.root_module();

        let data_section = plan
            .entry(root)
            .expect("missing scanned root module")
            .alloc_sections()
            .find(|section| section.name() == ".data")
            .expect("generated test dylib should contain a .data section")
            .id();
        let layout_section = plan
            .memory_layout()
            .module_section_id(root, data_section)
            .expect("missing planned .data section");
        let arena = plan.memory_layout_mut().create_arena(LayoutArena::new(
            4096,
            LayoutMemoryClass::WritableData,
            LayoutArenaSharing::Private,
        ));
        assert!(
            plan.memory_layout_mut()
                .assign_section_to_arena(layout_section, arena, 0),
            "failed to assign section into an arena for the negative test",
        );
        Ok(())
    };
    pipeline.push(&mut configure);

    let relocator = Relocator::<(), (), (), (), (), (), (), ()>::default();
    let mut planner = empty_relocation_plan;

    let err = context
        .load_with_scan(
            "root",
            &mut loader,
            &mut resolver,
            &mut pipeline,
            &relocator,
            &mut planner,
        )
        .expect_err("section-data modules must reject section-region placement");
    assert_eq!(observed_capability, Some(ModuleCapability::SectionData));
    assert!(
        err.to_string().contains("cannot assign sections to arenas"),
        "unexpected error: {err}",
    );
}
