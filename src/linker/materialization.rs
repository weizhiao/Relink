use super::{
    layout::{
        ArenaDescriptor, ArenaId, ArenaSharing, ClassPolicy, Materialization, MemoryClass,
        MemoryLayoutPlan, PackingPolicy, SectionId, SectionPlacement,
    },
    plan::{LinkPlan, ModuleId},
};
use crate::{LinkerError, Result, image::ModuleCapability, relocation::RelocationArch};
use alloc::{collections::BTreeMap, vec::Vec};

pub(crate) fn normalize_plan<K, Arch>(plan: &mut LinkPlan<K, Arch>) -> Result<()>
where
    K: Clone + Ord,
    Arch: RelocationArch,
{
    plan.try_for_each_module(|plan, module_id| {
        let mode = resolve_materialization_mode(&*plan, module_id)?;
        plan.set_materialization(module_id, mode);
        Ok(())
    })?;

    let section_region_modules = plan
        .modules_with_materialization(Materialization::SectionRegions)
        .collect::<Vec<_>>();
    if section_region_modules.is_empty() {
        return Ok(());
    }

    let policy = PackingPolicy::shared_huge_pages();
    let mut arena_state = ArenaState::new();

    record_existing_section_placements(plan, &mut arena_state, &section_region_modules);
    assign_missing_section_placements(plan, &mut arena_state, &section_region_modules, policy);

    Ok(())
}

fn resolve_materialization_mode<K>(
    plan: &LinkPlan<K, impl RelocationArch>,
    module_id: ModuleId,
) -> Result<Materialization>
where
    K: Clone + Ord,
{
    let capability = plan
        .module_capability(module_id)
        .expect("ordered layout referenced a module without capability metadata");
    let requested = plan
        .materialization(module_id)
        .unwrap_or_else(|| Materialization::default(capability));
    let has_section_placement = plan
        .module_layout(module_id)
        .alloc_sections()
        .iter()
        .any(|section_id| plan.placement(*section_id).is_some());

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

fn record_existing_section_placements<K>(
    plan: &LinkPlan<K, impl RelocationArch>,
    arena_state: &mut ArenaState,
    modules: &[ModuleId],
) where
    K: Clone + Ord,
{
    for module_id in modules.iter().copied() {
        let alloc_sections = plan.module_layout(module_id).alloc_sections().to_vec();
        for section_id in alloc_sections {
            if let Some(placement) = plan.placement(section_id) {
                arena_state.register_existing_section(plan, module_id, section_id, placement);
            }
        }
    }
}

fn assign_missing_section_placements<K>(
    plan: &mut LinkPlan<K, impl RelocationArch>,
    arena_state: &mut ArenaState,
    modules: &[ModuleId],
    policy: PackingPolicy,
) where
    K: Clone + Ord,
{
    for module_id in modules.iter().copied() {
        let alloc_sections = plan.module_layout(module_id).alloc_sections().to_vec();
        for section_id in alloc_sections {
            if plan.placement(section_id).is_none() {
                arena_state.assign_fallback_section(plan, module_id, section_id, policy);
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

    fn register_existing_section<K>(
        &mut self,
        plan: &LinkPlan<K, impl RelocationArch>,
        module_id: ModuleId,
        section_id: SectionId,
        placement: SectionPlacement,
    ) where
        K: Clone + Ord,
    {
        let metadata = plan.section_metadata(section_id);
        let memory_class = metadata
            .memory_class()
            .expect("fallback arena state found a non-alloc placed section");
        let arena = plan.memory_layout().arena(placement.arena());

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

    fn assign_fallback_section<K>(
        &mut self,
        plan: &mut LinkPlan<K, impl RelocationArch>,
        module_id: ModuleId,
        section_id: SectionId,
        policy: PackingPolicy,
    ) where
        K: Clone + Ord,
    {
        let (memory_class, alignment, size) = {
            let section = plan.section_metadata(section_id);
            (
                section
                    .memory_class()
                    .expect("fallback arena assignment encountered a non-alloc section"),
                section.alignment(),
                section.size(),
            )
        };
        let arena_id = self.ensure_arena(
            plan.memory_layout_mut(),
            module_id,
            policy.class_policy(memory_class),
            memory_class,
        );
        let offset = plan.memory_layout().next_offset(arena_id, alignment);
        let next_offset = offset
            .checked_add(size)
            .expect("fallback arena assignment overflowed while placing a section");

        assert!(
            plan.memory_layout_mut()
                .assign(section_id, arena_id, offset),
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

                let arena_id = layout.create_arena(ArenaDescriptor::new(
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
                    layout.create_arena(ArenaDescriptor::new(
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
    use crate::os::PageSize;

    #[test]
    fn fallback_shared_arena_reuses_existing_compatible_arena() {
        let mut plan = MemoryLayoutPlan::default();
        let arena_id = plan.create_arena(ArenaDescriptor::new(
            PageSize::Huge2MiB,
            MemoryClass::Code,
            ArenaSharing::Shared,
        ));
        let mut state = ArenaState::new();

        let selected = state.ensure_arena(
            &mut plan,
            ModuleId::new(0),
            ClassPolicy::new(PageSize::Huge2MiB, ArenaSharing::Shared),
            MemoryClass::Code,
        );

        assert_eq!(selected, arena_id);
        assert_eq!(plan.arena_pairs().count(), 1);
    }
}
