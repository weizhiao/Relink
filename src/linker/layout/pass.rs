use super::super::plan::LinkPass;
use super::{
    LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutClassPolicy, LayoutMemoryClass,
    LayoutPackingPolicy, LayoutRegion, LayoutRegionId, LayoutRegionPlacement, MemoryLayoutPlan,
};
use crate::Result;
use alloc::{collections::BTreeMap, vec::Vec};

/// Packs sections into logical regions and then maps those regions into arenas.
///
/// This is a strategy pass layered on top of the built-in layout core. The
/// caller chooses a packing policy here; the scan-first load path handles core
/// layout preparation and final derived-address rebuild internally.
#[derive(Debug, Clone, Copy)]
pub struct PackSectionsPass {
    policy: LayoutPackingPolicy,
}

impl Default for PackSectionsPass {
    #[inline]
    fn default() -> Self {
        Self::shared_huge_pages()
    }
}

impl PackSectionsPass {
    /// Creates a packing pass from an explicit arena policy.
    #[inline]
    pub const fn new(policy: LayoutPackingPolicy) -> Self {
        Self { policy }
    }

    /// Creates the default hugepage-oriented packing pass.
    #[inline]
    pub const fn shared_huge_pages() -> Self {
        Self::new(LayoutPackingPolicy::shared_huge_pages())
    }

    /// Returns the policy used by the pass.
    #[inline]
    pub const fn policy(&self) -> LayoutPackingPolicy {
        self.policy
    }
}

impl<K, D, Q: ?Sized> LinkPass<K, D, Q> for PackSectionsPass
where
    K: Clone + Ord,
    D: 'static,
{
    fn run(
        &mut self,
        plan: &mut super::super::plan::LinkPlan<K, D>,
        _queries: &mut Q,
    ) -> Result<()> {
        plan.ensure_section_layout();

        let module_sections = {
            let layout = plan
                .memory_layout()
                .expect("packing pass requires a seeded memory layout");
            plan.group_order()
                .iter()
                .filter_map(|key| {
                    layout
                        .module(key)
                        .map(|module| (key.clone(), module.alloc_sections().to_vec()))
                })
                .collect::<Vec<_>>()
        };

        let layout = plan
            .memory_layout_mut()
            .expect("packing pass requires a seeded memory layout");
        layout.clear_regions();

        let mut module_regions = BTreeMap::<K, BTreeMap<LayoutMemoryClass, LayoutRegionId>>::new();
        let mut region_order = Vec::<(K, LayoutRegionId)>::new();
        let mut region_offsets = BTreeMap::<LayoutRegionId, usize>::new();

        for (key, sections) in module_sections {
            for section_id in sections {
                let (memory_class, alignment, size) = {
                    let section = layout
                        .section_metadata(section_id)
                        .expect("packing pass referenced a missing section metadata record");
                    (section.memory_class(), section.alignment(), section.size())
                };
                let region_id = ensure_module_region(
                    layout,
                    &mut module_regions,
                    &mut region_order,
                    &key,
                    memory_class,
                );
                let offset = align_up(
                    region_offsets.get(&region_id).copied().unwrap_or(0),
                    alignment,
                )?;
                let next_offset = offset.checked_add(size).ok_or_else(|| {
                    crate::custom_error("section packing overflowed while assigning region offsets")
                })?;

                if !layout.assign_section_to_region(section_id, region_id, offset) {
                    return Err(crate::custom_error(
                        "section packing failed while attaching a section to its logical region",
                    ));
                }
                region_offsets.insert(region_id, next_offset);
            }
        }

        let mut shared_arenas = BTreeMap::<LayoutMemoryClass, LayoutArenaId>::new();
        let mut private_arenas = BTreeMap::<K, BTreeMap<LayoutMemoryClass, LayoutArenaId>>::new();
        let mut arena_offsets = BTreeMap::<LayoutArenaId, usize>::new();

        for (key, region_id) in region_order {
            let (memory_class, alignment, size) = {
                let region = layout
                    .region(region_id)
                    .expect("packing pass referenced a missing logical region");
                (region.memory_class(), region.alignment(), region.size())
            };
            let arena_id = allocate_region_arena(
                layout,
                &key,
                self.policy.class_policy(memory_class),
                memory_class,
                &mut shared_arenas,
                &mut private_arenas,
            );
            let offset = align_up(
                arena_offsets.get(&arena_id).copied().unwrap_or(0),
                alignment,
            )?;
            let next_offset = offset.checked_add(size).ok_or_else(|| {
                crate::custom_error("region packing overflowed while assigning arena offsets")
            })?;

            if !layout.place_region(
                region_id,
                LayoutRegionPlacement::new(arena_id, offset, size),
            ) {
                return Err(crate::custom_error(
                    "region packing failed while placing a logical region into an arena",
                ));
            }
            arena_offsets.insert(arena_id, next_offset);
        }

        Ok(())
    }
}

fn ensure_module_region<K>(
    layout: &mut MemoryLayoutPlan<K>,
    module_regions: &mut BTreeMap<K, BTreeMap<LayoutMemoryClass, LayoutRegionId>>,
    region_order: &mut Vec<(K, LayoutRegionId)>,
    key: &K,
    memory_class: LayoutMemoryClass,
) -> LayoutRegionId
where
    K: Clone + Ord,
{
    if let Some(region_id) = module_regions
        .get(key)
        .and_then(|regions| regions.get(&memory_class))
        .copied()
    {
        return region_id;
    }

    let region_id = layout
        .push_region(key, LayoutRegion::new(memory_class))
        .expect("packing pass referenced a missing module while creating a logical region");
    module_regions
        .entry(key.clone())
        .or_default()
        .insert(memory_class, region_id);
    region_order.push((key.clone(), region_id));
    region_id
}

fn allocate_region_arena<K>(
    layout: &mut MemoryLayoutPlan<K>,
    key: &K,
    class_policy: LayoutClassPolicy,
    memory_class: LayoutMemoryClass,
    shared_arenas: &mut BTreeMap<LayoutMemoryClass, LayoutArenaId>,
    private_arenas: &mut BTreeMap<K, BTreeMap<LayoutMemoryClass, LayoutArenaId>>,
) -> LayoutArenaId
where
    K: Clone + Ord,
{
    match class_policy.sharing() {
        LayoutArenaSharing::Shared => *shared_arenas.entry(memory_class).or_insert_with(|| {
            layout.push_arena(LayoutArena::new(
                class_policy.page_size(),
                memory_class,
                LayoutArenaSharing::Shared,
            ))
        }),
        LayoutArenaSharing::Private => *private_arenas
            .entry(key.clone())
            .or_default()
            .entry(memory_class)
            .or_insert_with(|| {
                layout.push_arena(LayoutArena::new(
                    class_policy.page_size(),
                    memory_class,
                    LayoutArenaSharing::Private,
                ))
            }),
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
        .ok_or_else(|| crate::custom_error("layout packing overflowed while aligning offsets"))
}
