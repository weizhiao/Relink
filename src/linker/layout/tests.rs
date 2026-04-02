use super::{
    LayoutAddress, LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutArenaUsage,
    LayoutClassPolicy, LayoutMemoryClass, LayoutPackingPolicy, LayoutRegion, LayoutRegionPlacement,
    LayoutRepairStatus, LayoutSectionData, LayoutSectionMetadata, LayoutSectionSource,
    MemoryLayoutPlan, ModuleLayout, PackSectionsPass, SectionRegionPlacement,
};
use crate::image::{
    ScannedMemoryData, ScannedMemoryKind, ScannedMemorySection, ScannedRelocation,
    ScannedRelocationAddend, ScannedRelocationFormat, ScannedRelocationSection, ScannedSectionId,
};
use crate::linker::plan::{LinkPass, LinkPlan};
use alloc::{collections::BTreeMap, vec, vec::Vec};

#[test]
fn module_layout_tracks_scanned_section_ids() {
    let layout = ModuleLayout::from_sections([
        (ScannedSectionId::new(3), super::LayoutSectionId::new(7)),
        (ScannedSectionId::new(4), super::LayoutSectionId::new(8)),
    ]);

    assert_eq!(layout.alloc_sections().len(), 2);
    assert_eq!(
        layout.section_id(ScannedSectionId::new(3)),
        Some(super::LayoutSectionId::new(7))
    );
    assert_eq!(
        layout.section_id(ScannedSectionId::new(4)),
        Some(super::LayoutSectionId::new(8))
    );
}

#[test]
fn memory_layout_plan_can_assign_and_clear_section_regions() {
    let mut layout = MemoryLayoutPlan::<&'static str>::new();
    let section_id = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(3)),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            64,
            16,
            false,
        ));
    layout.insert_module(
        "root",
        ModuleLayout::from_sections([(ScannedSectionId::new(3), section_id)]),
    );
    let region_id = layout
        .push_region(&"root", LayoutRegion::new(LayoutMemoryClass::Code))
        .unwrap();

    assert!(layout.assign_section_to_region(section_id, region_id, 0x2000));
    assert_eq!(
        layout
            .section_metadata(section_id)
            .and_then(|section| section.region()),
        Some(SectionRegionPlacement::new(region_id, 0x2000, 64))
    );
    assert_eq!(
        layout.clear_section_region(section_id),
        Some(SectionRegionPlacement::new(region_id, 0x2000, 64))
    );
    assert!(
        layout
            .section_metadata(section_id)
            .and_then(|section| section.region())
            .is_none()
    );
}

#[test]
fn memory_layout_plan_rejects_cross_dso_region_assignment() {
    let mut layout = MemoryLayoutPlan::<&'static str>::new();
    let root_section = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(1)),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            64,
            16,
            false,
        ));
    let dep_section = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(2)),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            64,
            16,
            false,
        ));
    layout.insert_module(
        "root",
        ModuleLayout::from_sections([(ScannedSectionId::new(1), root_section)]),
    );
    layout.insert_module(
        "dep",
        ModuleLayout::from_sections([(ScannedSectionId::new(2), dep_section)]),
    );

    let dep_region = layout
        .push_region(&"dep", LayoutRegion::new(LayoutMemoryClass::Code))
        .unwrap();

    assert!(!layout.assign_section_to_region(root_section, dep_region, 0));
    assert!(layout.section_region(root_section).is_none());
}

#[test]
fn memory_layout_plan_materializes_section_data_on_demand() {
    let mut layout = MemoryLayoutPlan::<&'static str>::new();
    let scanned_section = ScannedSectionId::new(5);
    let section_id = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(scanned_section),
            ".rodata",
            LayoutMemoryClass::ReadOnlyData,
            0,
            0,
            4,
            4,
            false,
        ));

    let data_id = layout
        .install_section_data(
            section_id,
            ScannedMemorySection::new(
                scanned_section,
                ".rodata".into(),
                ScannedMemoryKind::ReadOnlyData,
                0,
                0,
                4,
                4,
                ScannedMemoryData::Bytes(alloc::vec![1, 2, 3, 4].into_boxed_slice()),
            ),
        )
        .unwrap();

    assert_eq!(
        layout.section_metadata(section_id).unwrap().data(),
        Some(data_id)
    );
    assert_eq!(
        layout
            .section_data(data_id)
            .and_then(LayoutSectionData::bytes),
        Some([1_u8, 2, 3, 4].as_slice())
    );
}

#[test]
fn memory_layout_plan_assigns_index_based_arena_ids() {
    let mut plan = MemoryLayoutPlan::<&'static str>::new();
    let arena_id = plan.push_arena(LayoutArena::new(
        2 * 1024 * 1024,
        LayoutMemoryClass::ReadOnlyData,
        LayoutArenaSharing::Shared,
    ));

    assert_eq!(arena_id, LayoutArenaId::new(0));
    assert_eq!(plan.arenas().len(), 1);
    assert_eq!(plan.arena(arena_id).unwrap().page_size(), 2 * 1024 * 1024);
    assert_eq!(
        plan.arena(arena_id).unwrap().memory_class(),
        LayoutMemoryClass::ReadOnlyData
    );
    assert_eq!(
        plan.arena(arena_id).unwrap().sharing(),
        LayoutArenaSharing::Shared
    );
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
fn clear_regions_removes_regions_mappings_and_addresses() {
    let mut layout = MemoryLayoutPlan::<&'static str>::new();
    let section_id = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(1)),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            16,
            16,
            false,
        ));
    layout.insert_module(
        "root",
        ModuleLayout::from_sections([(ScannedSectionId::new(1), section_id)]),
    );

    let region_id = layout
        .push_region(&"root", LayoutRegion::new(LayoutMemoryClass::Code))
        .unwrap();
    let arena_id = layout.push_arena(LayoutArena::new(
        2 * 1024 * 1024,
        LayoutMemoryClass::Code,
        LayoutArenaSharing::Shared,
    ));
    layout.assign_section_to_region(section_id, region_id, 0x40);
    layout.place_region(
        region_id,
        LayoutRegionPlacement::new(arena_id, 0x2000, 0x80),
    );
    layout.rebuild_addresses();

    layout.clear_regions();

    assert!(layout.arenas().is_empty());
    assert_eq!(layout.region_entries().count(), 0);
    assert!(
        layout
            .section_metadata(section_id)
            .and_then(|section| section.region())
            .is_none()
    );
    assert!(layout.addresses().module(&"root").is_none());
}

#[test]
fn arena_usage_rounds_up_to_page_size() {
    let mut layout = MemoryLayoutPlan::<&'static str>::new();
    let section_id = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(3)),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            64,
            16,
            false,
        ));
    layout.insert_module(
        "root",
        ModuleLayout::from_sections([(ScannedSectionId::new(3), section_id)]),
    );
    let region_id = layout
        .push_region(&"root", LayoutRegion::new(LayoutMemoryClass::Code))
        .unwrap();
    let arena_id = layout.push_arena(LayoutArena::new(
        2 * 1024 * 1024,
        LayoutMemoryClass::Code,
        LayoutArenaSharing::Shared,
    ));
    layout.assign_section_to_region(section_id, region_id, 0x1ff0);
    layout.place_region(region_id, LayoutRegionPlacement::new(arena_id, 0, 0x2070));

    assert_eq!(
        layout.arena_usage(arena_id),
        Some(LayoutArenaUsage::new(1, 0x2070, 2 * 1024 * 1024))
    );
}

#[test]
fn prepare_layout_installs_an_empty_layout_when_needed() {
    let mut plan = LinkPlan::<&'static str, ()>::new("root", Vec::new(), BTreeMap::new());

    plan.prepare_layout().unwrap();

    assert!(plan.memory_layout().is_some());
    assert_eq!(plan.memory_layout().unwrap().modules().count(), 0);
}

#[test]
fn push_relocation_section_registers_metadata_in_the_target_module() {
    let mut layout = MemoryLayoutPlan::<&'static str>::new();
    layout.insert_module("root", ModuleLayout::new());

    let entry = ScannedRelocation::new(0x18, 1, 0, ScannedRelocationAddend::Explicit(0));
    let section = ScannedRelocationSection::new(
        ScannedSectionId::new(9),
        ".rela.text".into(),
        ScannedRelocationFormat::Rela,
        0x200,
        24,
        8,
        Some(ScannedSectionId::new(5)),
        Some(ScannedSectionId::new(7)),
        alloc::vec![entry].into_boxed_slice(),
    );

    let section_id = layout.push_relocation_section(&"root", section).unwrap();
    let duplicate_id = layout
        .push_relocation_section(
            &"root",
            ScannedRelocationSection::new(
                ScannedSectionId::new(9),
                ".rela.text".into(),
                ScannedRelocationFormat::Rela,
                0x200,
                24,
                8,
                Some(ScannedSectionId::new(5)),
                Some(ScannedSectionId::new(7)),
                alloc::vec![entry].into_boxed_slice(),
            ),
        )
        .unwrap();
    let metadata = layout.section_metadata(section_id).unwrap();
    let relocations = metadata.retained_relocations().unwrap();

    assert_eq!(duplicate_id, section_id);
    assert!(metadata.is_relocation());
    assert_eq!(relocations.format(), ScannedRelocationFormat::Rela);
    assert_eq!(relocations.target_section(), Some(ScannedSectionId::new(5)));
    assert_eq!(
        relocations.symbol_table_section(),
        Some(ScannedSectionId::new(7))
    );
    assert_eq!(relocations.entries(), [entry].as_slice());
    assert!(layout.supports_reorder_repair(&"root"));
    assert_eq!(
        layout.module_section_id(&"root", ScannedSectionId::new(9)),
        Some(section_id)
    );
}

#[test]
fn finalize_layout_derives_section_and_relocation_site_addresses() {
    let scanned_section = ScannedSectionId::new(5);
    let relocation_section_id = ScannedSectionId::new(9);

    let mut layout = MemoryLayoutPlan::<&'static str>::new();
    let section_id = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(scanned_section),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            64,
            16,
            false,
        ));
    layout.insert_module(
        "root",
        ModuleLayout::from_sections([(scanned_section, section_id)]),
    );

    let region_id = layout
        .push_region(&"root", LayoutRegion::new(LayoutMemoryClass::Code))
        .unwrap();
    layout.assign_section_to_region(section_id, region_id, 0);
    layout.place_region(
        region_id,
        LayoutRegionPlacement::new(LayoutArenaId::new(1), 0x1000, 64),
    );
    layout.push_relocation_section(
        &"root",
        ScannedRelocationSection::new(
            relocation_section_id,
            ".rela.text".into(),
            ScannedRelocationFormat::Rela,
            0,
            24,
            8,
            Some(scanned_section),
            None,
            alloc::vec![ScannedRelocation::new(
                0x18,
                1,
                0,
                ScannedRelocationAddend::Explicit(0),
            )]
            .into_boxed_slice(),
        ),
    );

    let mut plan = LinkPlan::<&'static str, ()>::new("root", vec!["root"], BTreeMap::new());
    plan.replace_memory_layout(layout);
    plan.finalize_layout();

    let layout = plan.memory_layout().unwrap();
    assert_eq!(layout.repair_status(&"root"), LayoutRepairStatus::Ready);
    assert_eq!(
        layout.section_address(&"root", scanned_section),
        Some(LayoutAddress::new(LayoutArenaId::new(1), 0x1000))
    );
    assert_eq!(
        layout.relocation_site_address(&"root", relocation_section_id, 0),
        Some(LayoutAddress::new(LayoutArenaId::new(1), 0x1018))
    );
    assert_eq!(
        layout
            .section_repair(&"root", scanned_section)
            .map(|repair| repair.original_address()),
        Some(0)
    );
    assert_eq!(
        layout
            .section_repair(&"root", scanned_section)
            .map(|repair| repair.address()),
        Some(LayoutAddress::new(LayoutArenaId::new(1), 0x1000))
    );
    let relocation_repair = layout
        .relocation_repair(&"root", relocation_section_id)
        .unwrap();
    assert_eq!(relocation_repair.sites().len(), 1);
    assert_eq!(
        relocation_repair.sites()[0].address(),
        LayoutAddress::new(LayoutArenaId::new(1), 0x1018)
    );
}

#[test]
fn pack_sections_pass_keeps_dso_regions_separate_but_shares_code_arena() {
    let mut plan = LinkPlan::<&'static str, ()>::new("root", vec!["root", "dep"], BTreeMap::new());
    let mut layout = MemoryLayoutPlan::<&'static str>::new();

    let root_text = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(1)),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            96,
            32,
            false,
        ));
    let root_data = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(2)),
            ".data",
            LayoutMemoryClass::WritableData,
            0,
            0,
            32,
            16,
            false,
        ));
    let dep_text = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(3)),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            64,
            64,
            false,
        ));

    layout.insert_module(
        "root",
        ModuleLayout::from_sections([
            (ScannedSectionId::new(1), root_text),
            (ScannedSectionId::new(2), root_data),
        ]),
    );
    layout.insert_module(
        "dep",
        ModuleLayout::from_sections([(ScannedSectionId::new(3), dep_text)]),
    );
    plan.replace_memory_layout(layout);

    let mut pass = PackSectionsPass::shared_huge_pages();
    pass.run(&mut plan, &mut ()).unwrap();
    plan.finalize_layout();

    let layout = plan.memory_layout().unwrap();
    let root_text_region = layout
        .module_section_region(&"root", ScannedSectionId::new(1))
        .unwrap();
    let dep_text_region = layout
        .module_section_region(&"dep", ScannedSectionId::new(3))
        .unwrap();
    let root_text_placement = layout
        .section_placement(&"root", ScannedSectionId::new(1))
        .unwrap();
    let dep_text_placement = layout
        .section_placement(&"dep", ScannedSectionId::new(3))
        .unwrap();
    let root_data_placement = layout
        .section_placement(&"root", ScannedSectionId::new(2))
        .unwrap();

    assert_ne!(root_text_region.region(), dep_text_region.region());
    assert_eq!(root_text_placement.arena(), dep_text_placement.arena());
    assert_ne!(root_text_placement.arena(), root_data_placement.arena());
    assert_eq!(
        layout.arena(root_text_placement.arena()).unwrap(),
        &LayoutArena::new(
            2 * 1024 * 1024,
            LayoutMemoryClass::Code,
            LayoutArenaSharing::Shared,
        )
    );
    assert_eq!(
        layout.arena(root_data_placement.arena()).unwrap(),
        &LayoutArena::new(
            4 * 1024,
            LayoutMemoryClass::WritableData,
            LayoutArenaSharing::Private,
        )
    );
    assert_eq!(dep_text_placement.offset(), 128);
    assert_eq!(
        layout.repair_status(&"root"),
        LayoutRepairStatus::MissingRetainedRelocations
    );
    assert_eq!(
        layout.repair_status(&"dep"),
        LayoutRepairStatus::MissingRetainedRelocations
    );
    let root_physical = layout.module_physical_layout(&"root").unwrap();
    let dep_physical = layout.module_physical_layout(&"dep").unwrap();
    assert!(root_physical.touches_arena(root_text_placement.arena()));
    assert!(dep_physical.touches_arena(dep_text_placement.arena()));
    assert_eq!(
        layout
            .physical()
            .modules_in_arena(root_text_placement.arena())
            .count(),
        2
    );
}

#[test]
fn build_physical_image_merges_multiple_dsos_into_shared_arena_bytes() {
    let mut layout = MemoryLayoutPlan::<&'static str>::new();

    let root_text = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(1)),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            4,
            4,
            false,
        ));
    let dep_text = layout
        .section_metadata_arena_mut()
        .insert(LayoutSectionMetadata::new(
            LayoutSectionSource::Scanned(ScannedSectionId::new(2)),
            ".text",
            LayoutMemoryClass::Code,
            0,
            0,
            4,
            4,
            false,
        ));

    layout.insert_module(
        "root",
        ModuleLayout::from_sections([(ScannedSectionId::new(1), root_text)]),
    );
    layout.insert_module(
        "dep",
        ModuleLayout::from_sections([(ScannedSectionId::new(2), dep_text)]),
    );

    let root_region = layout
        .push_region(&"root", LayoutRegion::new(LayoutMemoryClass::Code))
        .unwrap();
    let dep_region = layout
        .push_region(&"dep", LayoutRegion::new(LayoutMemoryClass::Code))
        .unwrap();
    let arena_id = layout.push_arena(LayoutArena::new(
        4096,
        LayoutMemoryClass::Code,
        LayoutArenaSharing::Shared,
    ));

    assert!(layout.assign_section_to_region(root_text, root_region, 0));
    assert!(layout.assign_section_to_region(dep_text, dep_region, 0));
    assert!(layout.place_region(root_region, LayoutRegionPlacement::new(arena_id, 0, 4)));
    assert!(layout.place_region(dep_region, LayoutRegionPlacement::new(arena_id, 8, 4)));

    layout.install_section_data(
        root_text,
        ScannedMemorySection::new(
            ScannedSectionId::new(1),
            ".text".into(),
            ScannedMemoryKind::Code,
            0,
            0,
            4,
            4,
            ScannedMemoryData::Bytes([1_u8, 2, 3, 4].into()),
        ),
    );
    layout.install_section_data(
        dep_text,
        ScannedMemorySection::new(
            ScannedSectionId::new(2),
            ".text".into(),
            ScannedMemoryKind::Code,
            0,
            0,
            4,
            4,
            ScannedMemoryData::Bytes([9_u8, 8, 7, 6].into()),
        ),
    );
    layout.rebuild_addresses();

    let image = layout.build_physical_image().unwrap().unwrap();
    let arena = image.arena_bytes(arena_id).unwrap();

    assert_eq!(&arena[0..4], [1_u8, 2, 3, 4].as_slice());
    assert_eq!(&arena[4..8], [0_u8, 0, 0, 0].as_slice());
    assert_eq!(&arena[8..12], [9_u8, 8, 7, 6].as_slice());
    assert!(image.module(&"root").unwrap().touches_arena(arena_id));
    assert!(image.module(&"dep").unwrap().touches_arena(arena_id));
}
