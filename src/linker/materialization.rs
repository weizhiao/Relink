use super::{
    layout::{
        Arena, ArenaId, ArenaSharing, ClassPolicy, Materialization, MemoryClass, MemoryLayoutPlan,
        ModuleLayout, PackingPolicy, SectionId, SectionPlacement,
    },
    plan::{LinkPlan, ModuleId},
};
use crate::{LinkerError, Result, image::ModuleCapability};
use alloc::collections::BTreeMap;

pub(crate) fn normalize_plan<K, D>(plan: &mut LinkPlan<K, D>) -> Result<()>
where
    K: Clone + Ord,
    D: 'static,
{
    let mut has_section_regions = false;

    plan.try_for_each_module(|plan, module_id| {
        let layout = plan.memory_layout();
        let module = layout.module(module_id);
        let mode = resolve_materialization_mode(&*plan, module_id, module)?;
        has_section_regions |= mode == Materialization::SectionRegions;
        plan.set_materialization(module_id, mode);
        Ok(())
    })?;

    if !has_section_regions {
        return Ok(());
    }

    let policy = PackingPolicy::shared_huge_pages();
    let mut arena_state = ArenaState::new();

    plan.try_for_each_module(|plan, module_id| {
        let layout = plan.memory_layout();
        if layout.materialization(module_id) != Some(Materialization::SectionRegions) {
            return Ok(());
        }

        for section_id in layout.module(module_id).alloc_sections().iter().copied() {
            if let Some(placement) = layout.placement(section_id) {
                arena_state.register_existing_section(layout, module_id, section_id, placement);
            }
        }
        Ok(())
    })?;

    plan.try_for_each_module(|plan, module_id| {
        let layout = plan.memory_layout();
        if layout.materialization(module_id) != Some(Materialization::SectionRegions) {
            return Ok(());
        }
        let alloc_sections = layout.module(module_id).alloc_sections().to_vec();
        for section_id in alloc_sections {
            if plan.memory_layout().placement(section_id).is_some() {
                continue;
            }
            arena_state.assign_fallback_section(
                plan.memory_layout_mut(),
                module_id,
                section_id,
                policy,
            );
        }
        Ok(())
    })?;

    Ok(())
}

fn resolve_materialization_mode<K, D>(
    plan: &LinkPlan<K, D>,
    module_id: ModuleId,
    module: &ModuleLayout,
) -> Result<Materialization>
where
    K: Clone + Ord,
    D: 'static,
{
    let layout = plan.memory_layout();
    let capability = plan
        .module_capability(module_id)
        .expect("ordered layout referenced a module without capability metadata");
    let requested = layout
        .materialization(module_id)
        .unwrap_or_else(|| Materialization::default(capability));
    let has_section_placement = module
        .alloc_sections()
        .iter()
        .any(|section_id| layout.placement(*section_id).is_some());

    match capability {
        ModuleCapability::Opaque | ModuleCapability::SectionData => {
            if has_section_placement {
                return Err(LinkerError::materialization(
                    "modules without section-reorder repair support cannot assign sections to arenas",
                )
                .into());
            }
            match requested {
                Materialization::WholeDsoRegion => Ok(Materialization::WholeDsoRegion),
                Materialization::SectionRegions => Err(LinkerError::materialization(
                    "modules without section-reorder repair support cannot use section regions",
                )
                .into()),
            }
        }
        ModuleCapability::SectionReorderable => {
            if has_section_placement {
                Ok(Materialization::SectionRegions)
            } else {
                Ok(requested)
            }
        }
    }
}

struct ArenaState {
    shared_arenas: BTreeMap<MemoryClass, ArenaId>,
    private_arenas: BTreeMap<(ModuleId, MemoryClass), ArenaId>,
    arena_offsets: BTreeMap<ArenaId, usize>,
}

impl ArenaState {
    fn new() -> Self {
        Self {
            shared_arenas: BTreeMap::new(),
            private_arenas: BTreeMap::new(),
            arena_offsets: BTreeMap::new(),
        }
    }

    fn register_existing_section(
        &mut self,
        layout: &MemoryLayoutPlan,
        module_id: ModuleId,
        section_id: SectionId,
        placement: SectionPlacement,
    ) {
        let metadata = layout.section(section_id);
        let memory_class = metadata
            .memory_class()
            .expect("fallback arena state found a non-alloc placed section");
        let arena = layout.arena(placement.arena());

        self.update_arena_end(
            placement.arena(),
            placement.offset().saturating_add(placement.size()),
        );
        match arena.sharing() {
            ArenaSharing::Shared => {
                self.shared_arenas
                    .entry(memory_class)
                    .or_insert(placement.arena());
            }
            ArenaSharing::Private => {
                self.private_arenas
                    .entry((module_id, memory_class))
                    .or_insert(placement.arena());
            }
        }
    }

    fn assign_fallback_section(
        &mut self,
        layout: &mut MemoryLayoutPlan,
        module_id: ModuleId,
        section_id: SectionId,
        policy: PackingPolicy,
    ) {
        let (memory_class, alignment, size) = {
            let section = layout.section(section_id);
            (
                section
                    .memory_class()
                    .expect("fallback arena assignment encountered a non-alloc section"),
                section.alignment(),
                section.size(),
            )
        };
        let arena_id = self.ensure_arena(
            layout,
            module_id,
            policy.class_policy(memory_class),
            memory_class,
        );
        let offset = layout.next_offset(arena_id, alignment);
        let next_offset = offset
            .checked_add(size)
            .expect("fallback arena assignment overflowed while placing a section");

        assert!(
            layout.assign(section_id, arena_id, offset),
            "fallback arena assignment failed while placing a section"
        );

        self.update_arena_end(arena_id, next_offset);
    }

    fn ensure_arena(
        &mut self,
        layout: &mut MemoryLayoutPlan,
        module_id: ModuleId,
        class_policy: ClassPolicy,
        memory_class: MemoryClass,
    ) -> ArenaId {
        match class_policy.sharing() {
            ArenaSharing::Shared => {
                if let Some(arena_id) = self.shared_arenas.get(&memory_class).copied() {
                    return arena_id;
                }

                if let Some(arena_id) = Self::find_shared_arena(layout, memory_class) {
                    self.update_arena_end(arena_id, layout.usage(arena_id).used_len());
                    self.shared_arenas.insert(memory_class, arena_id);
                    return arena_id;
                }

                let arena_id = layout.create_arena(Arena::new(
                    class_policy.page_size(),
                    memory_class,
                    ArenaSharing::Shared,
                ));
                self.shared_arenas.insert(memory_class, arena_id);
                arena_id
            }
            ArenaSharing::Private => *self
                .private_arenas
                .entry((module_id, memory_class))
                .or_insert_with(|| {
                    layout.create_arena(Arena::new(
                        class_policy.page_size(),
                        memory_class,
                        ArenaSharing::Private,
                    ))
                }),
        }
    }

    fn find_shared_arena(layout: &MemoryLayoutPlan, memory_class: MemoryClass) -> Option<ArenaId> {
        layout.arena_pairs().find_map(|(arena_id, arena)| {
            (arena.sharing() == ArenaSharing::Shared && arena.memory_class() == memory_class)
                .then_some(arena_id)
        })
    }

    fn update_arena_end(&mut self, arena_id: ArenaId, end: usize) {
        self.arena_offsets
            .entry(arena_id)
            .and_modify(|offset| *offset = (*offset).max(end))
            .or_insert(end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_shared_arena_reuses_existing_compatible_arena() {
        let mut layout = MemoryLayoutPlan::default();
        let arena_id = layout.create_arena(Arena::new(
            2 * 1024 * 1024,
            MemoryClass::Code,
            ArenaSharing::Shared,
        ));
        let mut state = ArenaState::new();

        let selected = state.ensure_arena(
            &mut layout,
            ModuleId::new(0),
            ClassPolicy::new(2 * 1024 * 1024, ArenaSharing::Shared),
            MemoryClass::Code,
        );

        assert_eq!(selected, arena_id);
        assert_eq!(layout.arenas().len(), 1);
    }
}
