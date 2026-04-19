mod support;

use elf_loader::{
    Loader,
    image::{LoadedCore, ModuleCapability},
    input::ElfBinary,
    linker::{
        KeyResolver, LinkContext, LinkPassPlan, LinkPipeline, ModuleMaterialization,
        RelocationInputs, RelocationRequest, ResolvedKey,
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
fn load_with_scan_legacy_path_applies_section_overrides_and_exposes_memory_slices() {
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
            .get(&"root")
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
    assert_eq!(loaded.memory_slices().len(), 1);
    assert_eq!(loaded.base(), loaded.memory_slices()[0].base());
    assert_eq!(loaded.mapped_len(), loaded.memory_slices()[0].len());
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
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
    assert_eq!(loaded.memory_slices().len(), 1);
    assert_eq!(loaded.base(), loaded.memory_slices()[0].base());
    assert_eq!(loaded.mapped_len(), loaded.memory_slices()[0].len());
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
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
            .get(&"root")
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

    assert!(loaded.memory_slices().len() > 1);
    assert!(
        loaded
            .memory_slices()
            .iter()
            .any(|slice| slice.base() != loaded.base()),
        "arena-backed load should expose multiple mapped slices",
    );
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
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
        Some(ModuleMaterialization::SectionRegions),
    );
    assert!(
        loaded.memory_slices().len() > 1,
        "section-region default should materialize alloc sections into mapped arenas",
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
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
            .get(&"root")
            .and_then(|module| module.section_headers())
            .is_none();
        plan.set_module_materialization(root, ModuleMaterialization::WholeDsoRegion);
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

    assert!(loaded.memory_slices().len() >= 1);
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
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

    assert!(loaded.memory_slices().len() >= 1);
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
            .get(&"root")
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
        plan.set_module_materialization(root, ModuleMaterialization::WholeDsoRegion);
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
        Some(ModuleMaterialization::WholeDsoRegion),
    );

    assert!(
        !loaded.memory_slices().is_empty(),
        "whole-DSO materialization should expose at least one mapped area",
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
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
            .get(&"root")
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
