use super::{
    Materialization, ModuleLayout, SectionId, SectionMetadata, SectionPlacement,
    layout::{DataAccess, MemoryLayoutPlan, SectionDataAccessRef},
};
use crate::{
    AlignedBytes, LinkerError, Result,
    aligned_bytes::ByteRepr,
    entity::{PrimaryMap, entity_ref},
    image::{ModuleCapability, ScannedDynamic, ScannedSectionId},
    relocation::RelocationArch,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

/// A stable id for one planned module stored inside a [`LinkPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleId(usize);
entity_ref!(ModuleId);

pub struct PlannedModule<K, Arch: RelocationArch> {
    key: K,
    module: ScannedDynamic<Arch::Layout>,
    direct_deps: Box<[ModuleId]>,
}

struct PendingPlannedModule<K, Arch: RelocationArch> {
    key: K,
    module: ScannedDynamic<Arch::Layout>,
    direct_deps: Box<[K]>,
}

impl<K, Arch> PendingPlannedModule<K, Arch>
where
    K: Ord,
    Arch: RelocationArch,
{
    fn resolve(self, module_ids: &BTreeMap<K, ModuleId>) -> PlannedModule<K, Arch> {
        let Self {
            key,
            module,
            direct_deps,
        } = self;
        let direct_deps = direct_deps
            .iter()
            .map(|dep_key| {
                *module_ids.get(dep_key).unwrap_or_else(|| {
                    panic!("planned module dependency referenced an unknown module key")
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        PlannedModule::new(key, module, direct_deps)
    }
}

impl<K, Arch> PlannedModule<K, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(
        key: K,
        module: ScannedDynamic<Arch::Layout>,
        direct_deps: Box<[ModuleId]>,
    ) -> Self {
        Self {
            key,
            module,
            direct_deps,
        }
    }

    #[inline]
    pub fn key(&self) -> &K {
        &self.key
    }

    #[inline]
    pub fn module(&self) -> &ScannedDynamic<Arch::Layout> {
        &self.module
    }

    #[inline]
    pub fn module_mut(&mut self) -> &mut ScannedDynamic<Arch::Layout> {
        &mut self.module
    }

    #[inline]
    pub fn direct_deps(&self) -> &[ModuleId] {
        &self.direct_deps
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (K, ScannedDynamic<Arch::Layout>, Box<[ModuleId]>) {
        (self.key, self.module, self.direct_deps)
    }
}

type LinkPlanParts<K, Arch> = (
    ModuleId,
    Vec<ModuleId>,
    PrimaryMap<ModuleId, PlannedModule<K, Arch>>,
    MemoryLayoutPlan,
);

fn section_data_entries<T: ByteRepr>(data: &AlignedBytes) -> Result<&[T]> {
    data.try_cast_slice::<T>().ok_or_else(|| {
        LinkerError::section_data("section data bytes do not match requested entry type").into()
    })
}

/// A global, pre-map link plan built from metadata discovery.
///
/// This plan owns the discovered logical module graph and accumulates later
/// planning decisions such as physical memory-layout plans or future
/// materialization policies.
pub(crate) struct LinkPlan<K, Arch: RelocationArch = crate::arch::NativeArch> {
    root: ModuleId,
    group_order: Vec<ModuleId>,
    module_ids: BTreeMap<K, ModuleId>,
    entries: PrimaryMap<ModuleId, PlannedModule<K, Arch>>,
    memory_layout: MemoryLayoutPlan,
}

impl<K, Arch> LinkPlan<K, Arch>
where
    K: Clone + Ord,
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(
        root: K,
        group_order: Vec<K>,
        mut entries: BTreeMap<K, (ScannedDynamic<Arch::Layout>, Box<[K]>)>,
    ) -> Self {
        let group_keys = group_order;
        let mut module_ids = BTreeMap::new();
        let mut group_order = Vec::with_capacity(group_keys.len());
        let mut pending_entries = PrimaryMap::default();
        for key in group_keys {
            let (module, direct_deps) = entries
                .remove(&key)
                .expect("scan plan group order referenced a missing discovered module");
            let id = pending_entries.push(PendingPlannedModule {
                key: key.clone(),
                module,
                direct_deps,
            });
            let previous = module_ids.insert(key, id);
            assert!(
                previous.is_none(),
                "scan plan discovered duplicate module key"
            );
            group_order.push(id);
        }

        let root = *module_ids
            .get(&root)
            .expect("scan plan root must exist in discovery order");

        let planned_entries = pending_entries.map_values(|_, pending| pending.resolve(&module_ids));
        assert!(
            entries.is_empty(),
            "scan plan contained modules that were not present in discovery order"
        );

        let memory_layout = MemoryLayoutPlan::from_scanned(
            planned_entries
                .iter()
                .map(|(id, entry)| (id, entry.module())),
        );
        Self {
            root,
            group_order,
            module_ids,
            entries: planned_entries,
            memory_layout,
        }
    }

    /// Returns the canonical root key of the plan.
    #[inline]
    pub(in crate::linker) fn root_key(&self) -> &K {
        self.module_key(self.root)
            .expect("planned root module must resolve to a key")
    }

    /// Returns the canonical root module id of the plan.
    #[inline]
    pub(crate) const fn root_module(&self) -> ModuleId {
        self.root
    }

    /// Returns the breadth-first module ids discovered from the root.
    #[inline]
    pub(crate) fn group_order(&self) -> &[ModuleId] {
        &self.group_order
    }

    pub(in crate::linker) fn modules_with_materialization(
        &self,
        mode: Materialization,
    ) -> impl Iterator<Item = ModuleId> + '_ {
        self.group_order
            .iter()
            .copied()
            .filter(move |module_id| self.materialization(*module_id) == Some(mode))
    }

    pub(crate) fn try_for_each_module(
        &mut self,
        mut f: impl FnMut(&mut Self, ModuleId) -> Result<()>,
    ) -> Result<()> {
        let group_len = self.group_order.len();
        for index in 0..group_len {
            let id = self.group_order[index];
            f(self, id)?;
        }
        Ok(())
    }

    /// Returns whether the plan contains `key`.
    #[inline]
    pub(in crate::linker) fn contains_key(&self, key: &K) -> bool {
        self.module_ids.contains_key(key)
    }

    /// Returns the stable module id for `key`.
    #[inline]
    pub(in crate::linker) fn module_id(&self, key: &K) -> Option<ModuleId> {
        self.module_ids.get(key).copied()
    }

    #[inline]
    pub(in crate::linker) fn module_key(&self, id: ModuleId) -> Option<&K> {
        self.entries.get(id).map(PlannedModule::key)
    }

    #[inline]
    pub(in crate::linker) fn get(&self, id: ModuleId) -> Option<&PlannedModule<K, Arch>> {
        self.entries.get(id)
    }

    #[inline]
    pub(in crate::linker) fn get_mut(
        &mut self,
        id: ModuleId,
    ) -> Option<&mut PlannedModule<K, Arch>> {
        self.entries.get_mut(id)
    }

    #[inline]
    pub(in crate::linker) fn entries(
        &self,
    ) -> impl Iterator<Item = (ModuleId, &PlannedModule<K, Arch>)> {
        self.entries.iter()
    }

    pub(crate) fn placement(&self, section: SectionId) -> Option<SectionPlacement> {
        self.memory_layout.placement(section)
    }

    /// Returns the physical memory-layout plan associated with this graph.
    #[inline]
    pub(in crate::linker) fn memory_layout(&self) -> &MemoryLayoutPlan {
        &self.memory_layout
    }

    /// Returns the physical memory-layout plan mutably.
    #[inline]
    pub(in crate::linker) fn memory_layout_mut(&mut self) -> &mut MemoryLayoutPlan {
        &mut self.memory_layout
    }

    /// Returns one module's layout view by stable module id.
    #[inline]
    pub(crate) fn module_layout(&self, id: ModuleId) -> &ModuleLayout {
        self.memory_layout.module(id)
    }

    /// Returns the owning module id for one stable section id.
    #[inline]
    pub(crate) fn section_owner(&self, section: SectionId) -> Option<ModuleId> {
        self.memory_layout.owner(section)
    }

    /// Returns the stable section id for one scanned section inside one module.
    #[inline]
    pub(crate) fn module_section_id(
        &self,
        module_id: ModuleId,
        id: impl Into<ScannedSectionId>,
    ) -> Option<SectionId> {
        self.memory_layout.section_id(module_id, id)
    }

    /// Returns one section metadata record by stable section id.
    #[inline]
    pub(crate) fn section_metadata(&self, section: SectionId) -> &SectionMetadata {
        self.memory_layout.section(section)
    }

    #[inline]
    pub(crate) fn module_capability(&self, id: ModuleId) -> Option<ModuleCapability> {
        self.get(id).map(|entry| entry.module().capability())
    }

    #[inline]
    pub(crate) fn materialization(&self, id: ModuleId) -> Option<Materialization> {
        self.memory_layout.materialization(id)
    }

    /// Selects the materialization mode for one module.
    #[inline]
    pub(crate) fn set_materialization(
        &mut self,
        id: ModuleId,
        mode: Materialization,
    ) -> Option<Materialization> {
        self.memory_layout.set_materialization(id, mode)
    }

    pub(in crate::linker) fn materialize_section_data(&mut self, section: SectionId) -> Result<()> {
        if self.memory_layout.data(section).is_some() {
            return Ok(());
        }

        let id = self.memory_layout.owner(section).ok_or_else(|| {
            LinkerError::section_data("section data requested for an unowned section")
        })?;
        let scanned_section = self.memory_layout.section(section).scanned_section();
        let entry = self.entries.get_mut(id).ok_or_else(|| {
            LinkerError::section_data("section data requested for a missing planned module")
        })?;
        if !entry.module().capability().has_section_data() {
            return Err(LinkerError::section_data(
                "section data requested for a module without section data",
            )
            .into());
        }

        let snapshot = entry
            .module_mut()
            .section_data(scanned_section)?
            .ok_or_else(|| {
                LinkerError::section_data("section data requested for a missing scanned section")
            })?;

        self.memory_layout.install_data(section, snapshot);
        Ok(())
    }

    pub(in crate::linker) fn with_disjoint_section_data<const N: usize, R>(
        &mut self,
        accesses: [(SectionId, DataAccess); N],
        f: impl FnOnce([SectionDataAccessRef<'_>; N]) -> Result<R>,
    ) -> Result<R> {
        for (index, (section, _)) in accesses.iter().enumerate() {
            if accesses[index + 1..]
                .iter()
                .any(|(other, _)| section == other)
            {
                return Err(LinkerError::duplicate_section_data_access().into());
            }
        }

        for &(section, access) in &accesses {
            self.materialize_section_data(section)?;
            if access == DataAccess::Write {
                self.memory_layout.mark_section_data_override(section);
            }
        }

        self.memory_layout
            .with_disjoint_section_data(accesses, f)
            .ok_or_else(LinkerError::missing_section_data_access)?
    }

    pub(in crate::linker) fn for_each_section_data<T, P>(
        &mut self,
        section: SectionId,
        mut prepare: impl FnMut(&T, &MemoryLayoutPlan) -> Result<Option<P>>,
        mut apply: impl FnMut(&mut Self, usize, P) -> Result<()>,
    ) -> Result<()>
    where
        T: ByteRepr,
    {
        self.materialize_section_data(section)?;
        let entry_count = {
            let plan = &self.memory_layout;
            let data = plan
                .data(section)
                .ok_or_else(|| LinkerError::section_data("section data was not materialized"))?;
            section_data_entries::<T>(data)?.len()
        };
        for index in 0..entry_count {
            let prepared = {
                let plan = &self.memory_layout;
                let data = plan.data(section).ok_or_else(|| {
                    LinkerError::section_data("section data was not materialized")
                })?;
                let entries = data.try_cast_slice::<T>().ok_or_else(|| {
                    LinkerError::section_data(
                        "section data bytes do not match requested entry type",
                    )
                })?;
                let entry = entries
                    .get(index)
                    .expect("section data entry index should remain valid");
                prepare(entry, plan)?
            };
            if let Some(prepared) = prepared {
                apply(self, index, prepared)?;
            }
        }
        Ok(())
    }

    /// Returns one section's data, materializing it on demand when needed.
    pub(crate) fn section_data(&mut self, section: SectionId) -> Result<&AlignedBytes> {
        self.materialize_section_data(section)?;
        self.memory_layout
            .data(section)
            .ok_or_else(|| LinkerError::section_data("section data was not materialized"))
            .map_err(Into::into)
    }

    /// Returns mutable section data, materializing it on demand when needed.
    pub(crate) fn section_data_mut(&mut self, section: SectionId) -> Result<&mut AlignedBytes> {
        self.materialize_section_data(section)?;
        self.memory_layout.mark_section_data_override(section);
        self.memory_layout
            .data_mut(section)
            .ok_or_else(|| LinkerError::section_data("section data was not materialized"))
            .map_err(Into::into)
    }

    #[inline]
    pub(in crate::linker) fn into_parts(self) -> LinkPlanParts<K, Arch> {
        (
            self.root,
            self.group_order,
            self.entries,
            self.memory_layout,
        )
    }
}
