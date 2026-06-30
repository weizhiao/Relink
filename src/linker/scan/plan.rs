use super::{
    Materialization, ModuleLayout, SectionId, SectionMetadata, SectionPlacement,
    layout::{DataAccess, MemoryLayoutPlan, SectionDataAccessRef},
};
use crate::{
    AlignedBytes, LinkerError, Result,
    elf::ElfSectionId,
    entity::{PrimaryMap, entity_ref},
    image::{ModuleCapability, ScannedDynamic},
    linker::storage::KeyId,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;

/// A stable id for one planned module stored inside a [`LinkPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::linker) struct ModuleId(usize);
entity_ref!(ModuleId);

pub struct PlannedModule<K, Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    key_id: KeyId,
    key: K,
    module: ScannedDynamic<Arch>,
    full_deps: Box<[KeyId]>,
    direct_deps: Box<[ModuleId]>,
    _marker: PhantomData<fn() -> Tls>,
}

type PlannedEntry<K, Arch> = (K, ScannedDynamic<Arch>, Box<[KeyId]>);
type PlannedEntries<K, Arch> = BTreeMap<KeyId, PlannedEntry<K, Arch>>;

fn resolve_direct_deps(
    module_ids: &BTreeMap<KeyId, ModuleId>,
    direct_deps: &[KeyId],
) -> Box<[ModuleId]> {
    direct_deps
        .iter()
        .filter_map(|dep_id| module_ids.get(dep_id).copied())
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

impl<K, Arch, Tls> PlannedModule<K, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(in crate::linker) fn new(
        key_id: KeyId,
        key: K,
        module: ScannedDynamic<Arch>,
        full_deps: Box<[KeyId]>,
        direct_deps: Box<[ModuleId]>,
    ) -> Self {
        Self {
            key_id,
            key,
            module,
            full_deps,
            direct_deps,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn key(&self) -> &K {
        &self.key
    }

    #[inline]
    pub(in crate::linker) fn scanned(&self) -> &ScannedDynamic<Arch> {
        &self.module
    }

    #[inline]
    pub(in crate::linker) fn direct_deps(&self) -> &[ModuleId] {
        &self.direct_deps
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (KeyId, K, ScannedDynamic<Arch>, Box<[KeyId]>) {
        (self.key_id, self.key, self.module, self.full_deps)
    }
}

type LinkPlanParts<K, Arch, Tls> = (
    ModuleId,
    Vec<ModuleId>,
    PrimaryMap<ModuleId, PlannedModule<K, Arch, Tls>>,
    MemoryLayoutPlan,
);

/// A global, pre-map link plan built from metadata discovery.
///
/// This plan owns the discovered logical module graph and accumulates later
/// planning decisions such as physical memory-layout plans or future
/// materialization policies.
pub(crate) struct LinkPlan<
    K,
    Arch: RelocationArch = crate::arch::NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    root: ModuleId,
    group_order: Vec<ModuleId>,
    module_ids: BTreeMap<K, ModuleId>,
    entries: PrimaryMap<ModuleId, PlannedModule<K, Arch, Tls>>,
    memory_layout: MemoryLayoutPlan,
}

impl<K, Arch, Tls> LinkPlan<K, Arch, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(in crate::linker) fn new(
        root: KeyId,
        group_order: Vec<KeyId>,
        mut entries: PlannedEntries<K, Arch>,
    ) -> Self {
        let group_ids = group_order;
        let mut module_ids = BTreeMap::new();
        let mut planned_ids = BTreeMap::new();
        let mut group_order = Vec::with_capacity(group_ids.len());
        let mut pending_entries = PrimaryMap::default();
        for key_id in group_ids {
            let (key, module, direct_deps) = entries
                .remove(&key_id)
                .expect("scan plan group order referenced a missing discovered module");
            let id = pending_entries.push((key_id, key.clone(), module, direct_deps));
            let previous = module_ids.insert(key, id);
            assert!(
                previous.is_none(),
                "scan plan discovered duplicate module key"
            );
            let previous = planned_ids.insert(key_id, id);
            assert!(
                previous.is_none(),
                "scan plan discovered duplicate module id"
            );
            group_order.push(id);
        }

        let root = *planned_ids
            .get(&root)
            .expect("scan plan root must exist in discovery order");

        let planned_entries =
            pending_entries.map_values(|_, (key_id, key, module, direct_deps)| {
                let plan_deps = resolve_direct_deps(&planned_ids, &direct_deps);
                PlannedModule::new(key_id, key, module, direct_deps, plan_deps)
            });
        assert!(
            entries.is_empty(),
            "scan plan contained modules that were not present in discovery order"
        );

        let memory_layout = MemoryLayoutPlan::from_scanned(
            planned_entries
                .iter()
                .map(|(id, entry)| (id, entry.scanned())),
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
    pub(in crate::linker) const fn root_module(&self) -> ModuleId {
        self.root
    }

    /// Returns the breadth-first module ids discovered from the root.
    #[inline]
    pub(in crate::linker) fn group_order(&self) -> &[ModuleId] {
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

    pub(in crate::linker) fn try_for_each_dynamic(
        &mut self,
        mut f: impl FnMut(&mut Self, ModuleId) -> Result<()>,
    ) -> Result<()> {
        let group_len = self.group_order.len();
        for index in 0..group_len {
            let id = self.group_order[index];
            if self.entries.get(id).is_none() {
                continue;
            }
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
    pub(in crate::linker) fn get(&self, id: ModuleId) -> Option<&PlannedModule<K, Arch, Tls>> {
        self.entries.get(id)
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
    pub(in crate::linker) fn module_layout(&self, id: ModuleId) -> &ModuleLayout {
        self.memory_layout.module(id)
    }

    /// Returns the owning module id for one stable section id.
    #[inline]
    pub(in crate::linker) fn section_owner(&self, section: SectionId) -> Option<ModuleId> {
        self.memory_layout.owner(section)
    }

    /// Returns the stable section id for one scanned section inside one module.
    #[inline]
    pub(in crate::linker) fn module_section_id(
        &self,
        module_id: ModuleId,
        id: ElfSectionId,
    ) -> Option<SectionId> {
        self.memory_layout.section_id(module_id, id)
    }

    /// Returns one section metadata record by stable section id.
    #[inline]
    pub(crate) fn section_metadata(&self, section: SectionId) -> &SectionMetadata {
        self.memory_layout.section(section)
    }

    #[inline]
    pub(in crate::linker) fn module_capability(&self, id: ModuleId) -> Option<ModuleCapability> {
        self.get(id).map(|entry| entry.scanned().capability())
    }

    #[inline]
    pub(in crate::linker) fn materialization(&self, id: ModuleId) -> Option<Materialization> {
        self.memory_layout.materialization(id)
    }

    /// Selects the materialization mode for one module.
    #[inline]
    pub(in crate::linker) fn set_materialization(
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
        let entry = self.entries.get(id).ok_or_else(|| {
            LinkerError::section_data("section data requested for a missing planned module")
        })?;
        let module = entry.scanned();
        if !module.capability().has_section_data() {
            return Err(LinkerError::section_data(
                "section data requested for a module without section data",
            )
            .into());
        }

        let snapshot = module.section_data(scanned_section)?.ok_or_else(|| {
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

    pub(in crate::linker) fn resize_section(
        &mut self,
        section: SectionId,
        byte_len: usize,
    ) -> Result<()> {
        self.materialize_section_data(section)?;
        self.memory_layout.resize_section(section, byte_len)?;
        self.memory_layout.mark_section_data_override(section);
        if self.memory_layout.section(section).is_allocated() {
            let owner = self.memory_layout.owner(section).ok_or_else(|| {
                LinkerError::section_data("section resize requested for an unowned section")
            })?;
            self.memory_layout
                .set_materialization(owner, Materialization::SectionRegions);
        }
        Ok(())
    }

    #[inline]
    pub(in crate::linker) fn into_parts(self) -> LinkPlanParts<K, Arch, Tls> {
        (
            self.root,
            self.group_order,
            self.entries,
            self.memory_layout,
        )
    }
}
