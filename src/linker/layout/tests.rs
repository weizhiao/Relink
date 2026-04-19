use super::{
    LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutArenaUsage, LayoutClassPolicy,
    LayoutMemoryClass, LayoutPackingPolicy, LayoutSectionMetadata, Materialization,
    MemoryLayoutPlan, SectionPlacement,
};
use crate::elf::{ElfRela, ElfSectionFlags, ElfSectionType};
use crate::linker::plan::LinkModuleId;
use core::mem::size_of;

const ROOT_MODULE: LinkModuleId = LinkModuleId::new(0);

fn section_flags(class: LayoutMemoryClass) -> ElfSectionFlags {
    let mut flags = ElfSectionFlags::ALLOC;
    match class {
        LayoutMemoryClass::Code => flags |= ElfSectionFlags::EXECINSTR,
        LayoutMemoryClass::WritableData | LayoutMemoryClass::ThreadLocalData => {
            flags |= ElfSectionFlags::WRITE;
        }
        LayoutMemoryClass::ReadOnlyData => {}
    }
    if class == LayoutMemoryClass::ThreadLocalData {
        flags |= ElfSectionFlags::TLS;
    }
    flags
}

fn alloc_section(
    layout: &mut MemoryLayoutPlan,
    section: usize,
    name: &str,
    class: LayoutMemoryClass,
    size: usize,
    alignment: usize,
    zero_fill: bool,
) -> super::LayoutSectionId {
    alloc_section_with_address(layout, section, name, class, 0, size, alignment, zero_fill)
}

fn alloc_section_with_address(
    layout: &mut MemoryLayoutPlan,
    section: usize,
    name: &str,
    class: LayoutMemoryClass,
    source_address: usize,
    size: usize,
    alignment: usize,
    zero_fill: bool,
) -> super::LayoutSectionId {
    layout.insert_section(
        ROOT_MODULE,
        LayoutSectionMetadata::new(
            section,
            name,
            if zero_fill {
                ElfSectionType::NOBITS
            } else {
                ElfSectionType::PROGBITS
            },
            section_flags(class),
            None::<super::LayoutSectionId>,
            None::<super::LayoutSectionId>,
            source_address,
            0,
            size,
            alignment,
        ),
    )
}

#[test]
#[should_panic(expected = "module layout referenced missing section metadata")]
fn module_layout_rejects_missing_section_metadata() {
    let layout = MemoryLayoutPlan::default();

    let _ = layout.module_layout_from_sections([(1, super::LayoutSectionId::new(0))]);
}

#[test]
fn memory_layout_plan_can_assign_and_clear_section_arenas() {
    let mut layout = MemoryLayoutPlan::default();
    let section = alloc_section(
        &mut layout,
        3,
        ".text",
        LayoutMemoryClass::Code,
        64,
        16,
        false,
    );
    let module = layout.module_layout_from_sections([(3, section)]);
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
fn module_layout_separates_non_allocated_and_allocated_relocations() {
    let mut plan = MemoryLayoutPlan::default();
    let text = alloc_section(
        &mut plan,
        3,
        ".text",
        LayoutMemoryClass::Code,
        64,
        16,
        false,
    );
    let retained_reloc = plan.insert_section(
        ROOT_MODULE,
        LayoutSectionMetadata::new(
            4,
            ".rela.text",
            ElfSectionType::RELA,
            ElfSectionFlags::empty(),
            Some(text),
            Some(text),
            0,
            0,
            size_of::<ElfRela>(),
            8,
        ),
    );
    let allocated_reloc = plan.insert_section(
        ROOT_MODULE,
        LayoutSectionMetadata::new(
            5,
            ".rela.dyn",
            ElfSectionType::RELA,
            ElfSectionFlags::ALLOC,
            Some(text),
            Some(text),
            0,
            0,
            size_of::<ElfRela>(),
            8,
        ),
    );

    let layout =
        plan.module_layout_from_sections([(3, text), (4, retained_reloc), (5, allocated_reloc)]);

    assert_eq!(layout.relocation_sections(), [retained_reloc].as_slice());
    assert_eq!(
        layout.allocated_relocation_sections(),
        [allocated_reloc].as_slice()
    );
}

#[test]
fn memory_layout_plan_rejects_incompatible_arena_assignment() {
    let mut layout = MemoryLayoutPlan::default();
    let section = alloc_section(
        &mut layout,
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
        &mut layout,
        5,
        ".rodata",
        LayoutMemoryClass::ReadOnlyData,
        4,
        4,
        false,
    );

    layout.install_section_data(section, alloc::vec![1, 2, 3, 4].into_boxed_slice());

    assert_eq!(
        layout.section_data(section).map(|data| data.as_ref()),
        Some([1_u8, 2, 3, 4].as_slice())
    );
    assert_eq!(
        layout.section_data(section).map(|data| data.as_ref()),
        Some([1_u8, 2, 3, 4].as_slice())
    );
}

#[test]
fn memory_layout_plan_keeps_materialization_when_replacing_module_layout() {
    let mut layout = MemoryLayoutPlan::default();
    let first = alloc_section(
        &mut layout,
        5,
        ".text",
        LayoutMemoryClass::Code,
        4,
        4,
        false,
    );
    let first_module = layout.module_layout_from_sections([(5, first)]);
    assert!(layout.insert_module(ROOT_MODULE, first_module).is_none());

    assert_eq!(
        layout.set_materialization(ROOT_MODULE, Materialization::SectionRegions),
        Some(Materialization::WholeDsoRegion)
    );

    let second = alloc_section(
        &mut layout,
        6,
        ".rodata",
        LayoutMemoryClass::ReadOnlyData,
        4,
        4,
        false,
    );
    let second_module = layout.module_layout_from_sections([(6, second)]);

    assert!(layout.insert_module(ROOT_MODULE, second_module).is_some());
    assert_eq!(
        layout.materialization(ROOT_MODULE),
        Some(Materialization::SectionRegions)
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
fn clear_arena_mappings_removes_placements() {
    let mut layout = MemoryLayoutPlan::default();
    let section = alloc_section(
        &mut layout,
        1,
        ".text",
        LayoutMemoryClass::Code,
        16,
        16,
        false,
    );
    let module = layout.module_layout_from_sections([(1, section)]);
    layout.insert_module(ROOT_MODULE, module);

    let arena = layout.push_arena(LayoutArena::new(
        2 * 1024 * 1024,
        LayoutMemoryClass::Code,
        LayoutArenaSharing::Shared,
    ));
    layout.assign_section_to_arena(section, arena, 0x40);

    layout.clear_arena_mappings();

    assert!(layout.arenas().is_empty());
    assert!(layout.section_placement(section).is_none());
}

#[test]
fn arena_usage_rounds_up_to_page_size() {
    let mut layout = MemoryLayoutPlan::default();
    let section = alloc_section(
        &mut layout,
        3,
        ".text",
        LayoutMemoryClass::Code,
        64,
        16,
        false,
    );
    let module = layout.module_layout_from_sections([(3, section)]);
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
