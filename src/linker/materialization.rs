use super::{
    layout::{
        LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutClassPolicy, LayoutMemoryClass,
        LayoutModuleMaterialization, LayoutPackingPolicy, LayoutSectionId, MemoryLayoutPlan,
        ModuleLayout, SectionPlacement,
    },
    plan::{LinkModuleId, LinkPlan},
};
use crate::{Result, image::ModuleCapability};
use alloc::collections::BTreeMap;

pub(crate) fn normalize_plan<K, D>(plan: &mut LinkPlan<K, D>) -> Result<()>
where
    K: Clone + Ord,
    D: 'static,
{
    let mut has_section_regions = false;

    plan.try_for_each_module(|plan, module_id| {
        let mode = {
            let layout = plan.memory_layout();
            let module = layout.module(module_id);
            resolve_materialization_mode(&*plan, module_id, module)?
        };
        has_section_regions |= mode == LayoutModuleMaterialization::SectionRegions;
        let _ = plan.set_module_materialization(module_id, mode);
        Ok(())
    })?;

    if !has_section_regions {
        return Ok(());
    }

    let policy = LayoutPackingPolicy::shared_huge_pages();
    let mut arena_state = FallbackArenaState::new();

    plan.try_for_each_module(|plan, module_id| {
        let layout = plan.memory_layout();
        if layout.module_materialization(module_id)
            != Some(LayoutModuleMaterialization::SectionRegions)
        {
            return Ok(());
        }

        for section_id in layout.module(module_id).alloc_sections().iter().copied() {
            if let Some(placement) = layout.section_placement(section_id) {
                arena_state.absorb_existing_section(layout, module_id, section_id, placement);
            }
        }
        Ok(())
    })?;

    plan.try_for_each_module(|plan, module_id| {
        let layout = plan.memory_layout();
        if layout.module_materialization(module_id)
            != Some(LayoutModuleMaterialization::SectionRegions)
        {
            return Ok(());
        }
        let alloc_sections = layout.module(module_id).alloc_sections().to_vec();
        for section_id in alloc_sections {
            if plan.memory_layout().section_placement(section_id).is_some() {
                continue;
            }
            assign_fallback_section(
                plan.memory_layout_mut(),
                module_id,
                section_id,
                policy,
                &mut arena_state,
            )?;
        }
        Ok(())
    })?;

    Ok(())
}

fn resolve_materialization_mode<K, D>(
    plan: &LinkPlan<K, D>,
    module_id: LinkModuleId,
    module: &ModuleLayout,
) -> Result<LayoutModuleMaterialization>
where
    K: Clone + Ord,
    D: 'static,
{
    let layout = plan.memory_layout();
    let capability = plan
        .module_capability(module_id)
        .expect("ordered layout referenced a module without capability metadata");
    let requested = layout
        .module_materialization(module_id)
        .expect("ordered layout referenced a module without materialization mode");
    let has_section_placement = module
        .alloc_sections()
        .iter()
        .any(|section_id| layout.section_placement(*section_id).is_some());

    match capability {
        ModuleCapability::Opaque | ModuleCapability::SectionData => {
            if has_section_placement {
                return Err(crate::custom_error(
                    "modules without section-reorder repair support cannot assign sections to arenas",
                ));
            }
            match requested {
                LayoutModuleMaterialization::WholeDsoRegion => {
                    Ok(LayoutModuleMaterialization::WholeDsoRegion)
                }
                LayoutModuleMaterialization::SectionRegions => Err(crate::custom_error(
                    "modules without section-reorder repair support cannot use section regions",
                )),
            }
        }
        ModuleCapability::SectionReorderable => {
            if has_section_placement || requested == LayoutModuleMaterialization::SectionRegions {
                Ok(LayoutModuleMaterialization::SectionRegions)
            } else {
                Ok(LayoutModuleMaterialization::WholeDsoRegion)
            }
        }
    }
}

fn assign_fallback_section(
    layout: &mut MemoryLayoutPlan,
    module_id: LinkModuleId,
    section_id: LayoutSectionId,
    policy: LayoutPackingPolicy,
    arena_state: &mut FallbackArenaState,
) -> Result<()> {
    let (memory_class, alignment, size) = {
        let section = layout.section_metadata(section_id);
        (
            section
                .memory_class()
                .expect("fallback arena assignment encountered a non-alloc section"),
            section.alignment(),
            section.size(),
        )
    };
    let arena_id = arena_state.ensure_arena(
        layout,
        module_id,
        policy.class_policy(memory_class),
        memory_class,
    );
    let offset = arena_state.next_offset(arena_id, alignment)?;
    let next_offset = offset
        .checked_add(size)
        .expect("fallback arena assignment overflowed while placing a section");

    assert!(
        layout.assign_section_to_arena(section_id, arena_id, offset),
        "fallback arena assignment failed while placing a section"
    );

    arena_state.update_arena_end(arena_id, next_offset);
    Ok(())
}

struct FallbackArenaState {
    shared_arenas: BTreeMap<LayoutMemoryClass, LayoutArenaId>,
    private_arenas: BTreeMap<(LinkModuleId, LayoutMemoryClass), LayoutArenaId>,
    arena_offsets: BTreeMap<LayoutArenaId, usize>,
}

impl FallbackArenaState {
    fn new() -> Self {
        Self {
            shared_arenas: BTreeMap::new(),
            private_arenas: BTreeMap::new(),
            arena_offsets: BTreeMap::new(),
        }
    }

    fn absorb_existing_section(
        &mut self,
        layout: &MemoryLayoutPlan,
        module_id: LinkModuleId,
        section_id: LayoutSectionId,
        placement: SectionPlacement,
    ) {
        let metadata = layout.section_metadata(section_id);
        let memory_class = metadata
            .memory_class()
            .expect("fallback arena state found a non-alloc placed section");
        let arena = layout.arena(placement.arena());

        self.update_arena_end(
            placement.arena(),
            placement.offset().saturating_add(placement.size()),
        );
        self.remember_arena(module_id, memory_class, placement.arena(), arena);
    }

    fn remember_arena(
        &mut self,
        module_id: LinkModuleId,
        memory_class: LayoutMemoryClass,
        arena_id: LayoutArenaId,
        arena: &LayoutArena,
    ) {
        match arena.sharing() {
            LayoutArenaSharing::Shared => {
                self.shared_arenas.entry(memory_class).or_insert(arena_id);
            }
            LayoutArenaSharing::Private => {
                self.private_arenas
                    .entry((module_id, memory_class))
                    .or_insert(arena_id);
            }
        }
    }

    fn ensure_arena(
        &mut self,
        layout: &mut MemoryLayoutPlan,
        module_id: LinkModuleId,
        class_policy: LayoutClassPolicy,
        memory_class: LayoutMemoryClass,
    ) -> LayoutArenaId {
        match class_policy.sharing() {
            LayoutArenaSharing::Shared => {
                if let Some(arena_id) = self.shared_arenas.get(&memory_class).copied() {
                    return arena_id;
                }

                if let Some(arena_id) = Self::find_shared_arena(layout, memory_class) {
                    self.remember_existing_arena_end(layout, arena_id);
                    self.shared_arenas.insert(memory_class, arena_id);
                    return arena_id;
                }

                let arena_id = layout.create_arena(LayoutArena::new(
                    class_policy.page_size(),
                    memory_class,
                    LayoutArenaSharing::Shared,
                ));
                self.shared_arenas.insert(memory_class, arena_id);
                arena_id
            }
            LayoutArenaSharing::Private => *self
                .private_arenas
                .entry((module_id, memory_class))
                .or_insert_with(|| {
                    layout.create_arena(LayoutArena::new(
                        class_policy.page_size(),
                        memory_class,
                        LayoutArenaSharing::Private,
                    ))
                }),
        }
    }

    fn find_shared_arena(
        layout: &MemoryLayoutPlan,
        memory_class: LayoutMemoryClass,
    ) -> Option<LayoutArenaId> {
        layout.arena_entries().find_map(|(arena_id, arena)| {
            (arena.sharing() == LayoutArenaSharing::Shared && arena.memory_class() == memory_class)
                .then_some(arena_id)
        })
    }

    fn remember_existing_arena_end(&mut self, layout: &MemoryLayoutPlan, arena_id: LayoutArenaId) {
        self.update_arena_end(arena_id, layout.arena_usage(arena_id).used_len());
    }

    fn next_offset(&self, arena_id: LayoutArenaId, alignment: usize) -> Result<usize> {
        align_up(
            self.arena_offsets.get(&arena_id).copied().unwrap_or(0),
            alignment,
        )
    }

    fn update_arena_end(&mut self, arena_id: LayoutArenaId, end: usize) {
        self.arena_offsets
            .entry(arena_id)
            .and_modify(|offset| *offset = (*offset).max(end))
            .or_insert(end);
    }
}

fn align_up(value: usize, alignment: usize) -> Result<usize> {
    let alignment = alignment.max(1);
    let remainder = value % alignment;
    if remainder == 0 {
        return Ok(value);
    }

    value
        .checked_add(alignment - remainder)
        .ok_or_else(|| crate::custom_error("arena assignment overflowed while aligning offsets"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_shared_arena_reuses_existing_compatible_arena() {
        let mut layout = MemoryLayoutPlan::default();
        let arena_id = layout.create_arena(LayoutArena::new(
            2 * 1024 * 1024,
            LayoutMemoryClass::Code,
            LayoutArenaSharing::Shared,
        ));
        let mut state = FallbackArenaState::new();

        let selected = state.ensure_arena(
            &mut layout,
            LinkModuleId::new(0),
            LayoutClassPolicy::new(2 * 1024 * 1024, LayoutArenaSharing::Shared),
            LayoutMemoryClass::Code,
        );

        assert_eq!(selected, arena_id);
        assert_eq!(layout.arenas().len(), 1);
    }
}
