use super::{
    LayoutAddress, LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutArenaUsage,
    LayoutClassPolicy, LayoutMemoryClass, LayoutModuleMaterialization, LayoutPackingPolicy,
    LayoutSectionArena, LayoutSectionData, LayoutSectionKind, LayoutSectionMetadata,
    MemoryLayoutPlan, ModuleLayout, SectionPlacement,
};
use crate::elf::{ElfRela, REL_BIT};
use crate::image::ModuleCapability;
use crate::linker::plan::LinkModuleId;
use alloc::{boxed::Box, vec::Vec};
use core::mem::size_of;

const ROOT_MODULE: LinkModuleId = LinkModuleId::new(0);

fn alloc_section(
    sections: &mut LayoutSectionArena,
    section: usize,
    name: &str,
    class: LayoutMemoryClass,
    size: usize,
    alignment: usize,
    zero_fill: bool,
) -> super::LayoutSectionId {
    alloc_section_with_address(
        sections, section, name, class, 0, size, alignment, zero_fill,
    )
}

fn alloc_section_with_address(
    sections: &mut LayoutSectionArena,
    section: usize,
    name: &str,
    class: LayoutMemoryClass,
    original_address: usize,
    size: usize,
    alignment: usize,
    zero_fill: bool,
) -> super::LayoutSectionId {
    sections.insert(
        ROOT_MODULE,
        LayoutSectionMetadata::new(
            section,
            name,
            LayoutSectionKind::Allocated(class),
            None::<super::LayoutSectionId>,
            None::<super::LayoutSectionId>,
            original_address,
            0,
            size,
            alignment,
            zero_fill,
        ),
    )
}

fn relocation_metadata(
    sections: &mut LayoutSectionArena,
    section: usize,
    name: &str,
    target: Option<super::LayoutSectionId>,
    symtab: Option<super::LayoutSectionId>,
) -> super::LayoutSectionId {
    sections.insert(
        ROOT_MODULE,
        LayoutSectionMetadata::new(
            section,
            name,
            LayoutSectionKind::RetainedRelocation,
            symtab,
            target,
            0,
            0,
            size_of::<ElfRela>(),
            8,
            false,
        ),
    )
}

fn rela_bytes(
    offset: usize,
    relocation_type: usize,
    symbol_index: usize,
    addend: isize,
) -> Box<[u8]> {
    let r_info = (symbol_index << REL_BIT) | relocation_type;
    let mut bytes = Vec::with_capacity(size_of::<ElfRela>());

    #[cfg(target_pointer_width = "64")]
    {
        bytes.extend_from_slice(&(offset as u64).to_ne_bytes());
        bytes.extend_from_slice(&(r_info as u64).to_ne_bytes());
        bytes.extend_from_slice(&(addend as i64).to_ne_bytes());
    }

    #[cfg(not(target_pointer_width = "64"))]
    {
        bytes.extend_from_slice(&(offset as u32).to_ne_bytes());
        bytes.extend_from_slice(&(r_info as u32).to_ne_bytes());
        bytes.extend_from_slice(&(addend as i32).to_ne_bytes());
    }

    bytes.into_boxed_slice()
}

#[test]
fn module_layout_tracks_scanned_section_ids_and_kinds() {
    let mut sections = LayoutSectionArena::new();
    let text = alloc_section(
        &mut sections,
        3,
        ".text",
        LayoutMemoryClass::Code,
        64,
        16,
        false,
    );
    let reloc = relocation_metadata(&mut sections, 4, ".rela.text", Some(text), Some(text));
    let debug = sections.insert(
        ROOT_MODULE,
        LayoutSectionMetadata::new(
            5,
            ".debug_info",
            LayoutSectionKind::NonAllocated,
            None::<super::LayoutSectionId>,
            None::<super::LayoutSectionId>,
            0,
            0,
            24,
            1,
            false,
        ),
    );

    let layout = ModuleLayout::from_sections([(3, text), (4, reloc), (5, debug)], &sections);

    assert_eq!(layout.section_entries().count(), 3);
    assert_eq!(layout.alloc_sections(), [text].as_slice());
    assert_eq!(layout.relocation_sections(), [reloc].as_slice());
    assert_eq!(layout.section_id(3), Some(text));
    assert_eq!(layout.section_id(4), Some(reloc));
    assert_eq!(layout.section_id(5), Some(debug));
}

#[test]
#[should_panic(expected = "module layout referenced missing section metadata")]
fn module_layout_rejects_missing_section_metadata() {
    let sections = LayoutSectionArena::new();

    let _ = ModuleLayout::from_sections([(1, super::LayoutSectionId::new(0))], &sections);
}

#[test]
fn memory_layout_plan_can_assign_and_clear_section_arenas() {
    let mut layout = MemoryLayoutPlan::default();
    let section = alloc_section(
        layout.sections_mut(),
        3,
        ".text",
        LayoutMemoryClass::Code,
        64,
        16,
        false,
    );
    let module = ModuleLayout::from_sections([(3, section)], layout.sections());
    layout.insert_module(ROOT_MODULE, module);
    let arena = layout.create_arena(LayoutArena::new(
        2 * 1024 * 1024,
        LayoutMemoryClass::Code,
        LayoutArenaSharing::Shared,
    ));

    assert!(layout.assign_section_to_arena(section, arena, 0x2000));
    assert_eq!(
        layout.section_placement(section),
        Some(SectionPlacement::new(arena, 0x2000, 64))
    );
    assert_eq!(
        layout.clear_section_arena(section),
        Some(SectionPlacement::new(arena, 0x2000, 64))
    );
    assert!(layout.section_placement(section).is_none());
}

#[test]
fn memory_layout_plan_rejects_incompatible_arena_assignment() {
    let mut layout = MemoryLayoutPlan::default();
    let section = alloc_section(
        layout.sections_mut(),
        1,
        ".text",
        LayoutMemoryClass::Code,
        64,
        16,
        false,
    );
    let readonly_arena = layout.create_arena(LayoutArena::new(
        4096,
        LayoutMemoryClass::ReadOnlyData,
        LayoutArenaSharing::Private,
    ));

    assert!(!layout.assign_section_to_arena(section, readonly_arena, 0));
    assert!(layout.section_placement(section).is_none());
}

#[test]
fn memory_layout_plan_materializes_section_data_on_demand() {
    let mut layout = MemoryLayoutPlan::default();
    let section = alloc_section(
        layout.sections_mut(),
        5,
        ".rodata",
        LayoutMemoryClass::ReadOnlyData,
        4,
        4,
        false,
    );

    layout
        .sections_mut()
        .install_scanned_data(section, alloc::vec![1, 2, 3, 4].into_boxed_slice());

    assert_eq!(
        layout
            .sections()
            .data(section)
            .and_then(LayoutSectionData::bytes),
        Some([1_u8, 2, 3, 4].as_slice())
    );
    assert_eq!(
        layout
            .sections()
            .data(section)
            .and_then(LayoutSectionData::bytes),
        Some([1_u8, 2, 3, 4].as_slice())
    );
}

#[test]
fn memory_layout_plan_keeps_materialization_when_replacing_module_layout() {
    let mut layout = MemoryLayoutPlan::default();
    let first = alloc_section(
        layout.sections_mut(),
        5,
        ".text",
        LayoutMemoryClass::Code,
        4,
        4,
        false,
    );
    let first_module = ModuleLayout::from_sections([(5, first)], layout.sections());
    assert!(layout.insert_module(ROOT_MODULE, first_module).is_none());

    assert_eq!(
        layout.set_module_materialization(ROOT_MODULE, LayoutModuleMaterialization::SectionRegions),
        Some(LayoutModuleMaterialization::WholeDsoRegion)
    );

    let second = alloc_section(
        layout.sections_mut(),
        6,
        ".rodata",
        LayoutMemoryClass::ReadOnlyData,
        4,
        4,
        false,
    );
    let second_module = ModuleLayout::from_sections([(6, second)], layout.sections());

    assert!(layout.insert_module(ROOT_MODULE, second_module).is_some());
    assert_eq!(
        layout.module_materialization(ROOT_MODULE),
        Some(LayoutModuleMaterialization::SectionRegions)
    );
    assert_eq!(layout.module_section_id(ROOT_MODULE, 6), Some(second));
}

#[test]
fn memory_layout_plan_assigns_index_based_arena_ids() {
    let mut plan = MemoryLayoutPlan::default();
    let arena_id = plan.push_arena(LayoutArena::new(
        2 * 1024 * 1024,
        LayoutMemoryClass::ReadOnlyData,
        LayoutArenaSharing::Shared,
    ));

    assert_eq!(arena_id, LayoutArenaId::new(0));
    assert_eq!(plan.arenas().len(), 1);
    assert_eq!(plan.arena(arena_id).page_size(), 2 * 1024 * 1024);
    assert_eq!(
        plan.arena(arena_id).memory_class(),
        LayoutMemoryClass::ReadOnlyData
    );
    assert_eq!(plan.arena(arena_id).sharing(), LayoutArenaSharing::Shared);
}

#[test]
fn layout_packing_policy_defaults_to_shared_huge_pages() {
    let policy = LayoutPackingPolicy::shared_huge_pages();

    assert_eq!(
        policy.class_policy(LayoutMemoryClass::Code),
        LayoutClassPolicy::new(2 * 1024 * 1024, LayoutArenaSharing::Shared)
    );
    assert_eq!(
        policy.class_policy(LayoutMemoryClass::ReadOnlyData),
        LayoutClassPolicy::new(2 * 1024 * 1024, LayoutArenaSharing::Shared)
    );
    assert_eq!(
        policy.class_policy(LayoutMemoryClass::WritableData),
        LayoutClassPolicy::new(4 * 1024, LayoutArenaSharing::Private)
    );
}

#[test]
fn clear_arena_mappings_removes_placements_and_derived_state() {
    let mut layout = MemoryLayoutPlan::default();
    let section = alloc_section(
        layout.sections_mut(),
        1,
        ".text",
        LayoutMemoryClass::Code,
        16,
        16,
        false,
    );
    let module = ModuleLayout::from_sections([(1, section)], layout.sections());
    layout.insert_module(ROOT_MODULE, module);

    let arena = layout.push_arena(LayoutArena::new(
        2 * 1024 * 1024,
        LayoutMemoryClass::Code,
        LayoutArenaSharing::Shared,
    ));
    layout.assign_section_to_arena(section, arena, 0x40);
    layout
        .rebuild_derived_state(|_| Some(ModuleCapability::SectionData), |_, _| Ok(()))
        .unwrap();

    layout.clear_arena_mappings();

    assert!(layout.arenas().is_empty());
    assert!(layout.section_placement(section).is_none());
}

#[test]
fn arena_usage_rounds_up_to_page_size() {
    let mut layout = MemoryLayoutPlan::default();
    let section = alloc_section(
        layout.sections_mut(),
        3,
        ".text",
        LayoutMemoryClass::Code,
        64,
        16,
        false,
    );
    let module = ModuleLayout::from_sections([(3, section)], layout.sections());
    layout.insert_module(ROOT_MODULE, module);
    let arena = layout.push_arena(LayoutArena::new(
        2 * 1024 * 1024,
        LayoutMemoryClass::Code,
        LayoutArenaSharing::Shared,
    ));
    layout.assign_section_to_arena(section, arena, 0x1ff0);

    assert_eq!(
        layout.arena_usage(arena),
        LayoutArenaUsage::new(1, 0x2030, 2 * 1024 * 1024)
    );
}

#[test]
fn finalize_layout_derives_section_and_relocation_site_addresses() {
    let mut layout = MemoryLayoutPlan::default();
    let text = alloc_section(
        layout.sections_mut(),
        5,
        ".text",
        LayoutMemoryClass::Code,
        64,
        16,
        false,
    );
    let reloc = relocation_metadata(layout.sections_mut(), 9, ".rela.text", Some(text), None);
    let module = ModuleLayout::from_sections([(5, text), (9, reloc)], layout.sections());
    layout.insert_module(ROOT_MODULE, module);
    layout
        .sections_mut()
        .install_scanned_data(reloc, rela_bytes(0x18, 1, 0, 0));
    layout.create_arena(LayoutArena::new(
        4096,
        LayoutMemoryClass::Code,
        LayoutArenaSharing::Shared,
    ));
    layout.place_section_in_arena(
        text,
        SectionPlacement::new(LayoutArenaId::new(0), 0x1000, 64),
    );

    layout
        .rebuild_derived_state(
            |_| Some(ModuleCapability::SectionReorderable),
            |_, _| Ok(()),
        )
        .unwrap();

    assert_eq!(
        layout
            .section_placement(text)
            .map(SectionPlacement::address),
        Some(LayoutAddress::new(LayoutArenaId::new(0), 0x1000))
    );

    let derived = layout.module_derived(ROOT_MODULE).unwrap();
    let relocation_repair = derived
        .relocation_repairs()
        .find_map(|(section, repair)| (*section == reloc).then_some(repair))
        .unwrap();
    assert_eq!(relocation_repair.sites().len(), 1);
    assert_eq!(
        relocation_repair.sites()[0].address(),
        LayoutAddress::new(LayoutArenaId::new(0), 0x1018)
    );
}

#[test]
fn retained_relocation_uses_sh_info_target_without_cross_section_fallback() {
    let mut layout = MemoryLayoutPlan::default();
    let text = alloc_section_with_address(
        layout.sections_mut(),
        5,
        ".text",
        LayoutMemoryClass::Code,
        0x1000,
        64,
        16,
        false,
    );
    let data = alloc_section_with_address(
        layout.sections_mut(),
        6,
        ".data",
        LayoutMemoryClass::WritableData,
        0x2000,
        64,
        16,
        false,
    );
    let reloc = relocation_metadata(layout.sections_mut(), 9, ".rela.text", Some(text), None);
    let module = ModuleLayout::from_sections([(5, text), (6, data), (9, reloc)], layout.sections());
    layout.insert_module(ROOT_MODULE, module);
    layout
        .sections_mut()
        .install_scanned_data(reloc, rela_bytes(0x2018, 1, 0, 0));
    layout.create_arena(LayoutArena::new(
        4096,
        LayoutMemoryClass::Code,
        LayoutArenaSharing::Shared,
    ));
    layout.create_arena(LayoutArena::new(
        4096,
        LayoutMemoryClass::WritableData,
        LayoutArenaSharing::Private,
    ));
    layout.place_section_in_arena(
        text,
        SectionPlacement::new(LayoutArenaId::new(0), 0x1000, 64),
    );
    layout.place_section_in_arena(
        data,
        SectionPlacement::new(LayoutArenaId::new(1), 0x2000, 64),
    );

    layout
        .rebuild_derived_state(
            |_| Some(ModuleCapability::SectionReorderable),
            |_, _| Ok(()),
        )
        .unwrap();

    let derived = layout.module_derived(ROOT_MODULE).unwrap();
    let relocation_repair = derived
        .relocation_repairs()
        .find_map(|(section, repair)| (*section == reloc).then_some(repair))
        .unwrap();
    assert!(relocation_repair.sites().is_empty());
}
