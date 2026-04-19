use super::{
    LayoutSectionId, LayoutSectionMetadata, Materialization, MemoryLayoutPlan, ModuleLayout,
};
use crate::{
    AlignedBytes, LinkerError, Result,
    entity::{PrimaryMap, entity_ref},
    image::{ModuleCapability, ScannedDylib},
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

/// A stable id for one planned module stored inside a [`LinkPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkModuleId(usize);
entity_ref!(LinkModuleId);

/// The minimum module capability required by one planning pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LinkPassScope {
    /// Run over every scanned module, including opaque modules.
    #[default]
    Any,
    /// Run only over modules that expose section metadata/data.
    SectionData,
    /// Run only over modules that support section-reorder repair.
    SectionReorderable,
}

impl LinkPassScope {
    #[inline]
    pub(crate) const fn matches(self, capability: ModuleCapability) -> bool {
        match self {
            Self::Any => true,
            Self::SectionData => !matches!(capability, ModuleCapability::Opaque),
            Self::SectionReorderable => matches!(capability, ModuleCapability::SectionReorderable),
        }
    }
}

/// A capability-filtered mutable view over one link plan during pass execution.
pub struct LinkPassPlan<'a, K, D: 'static> {
    plan: &'a mut LinkPlan<K, D>,
    scope: LinkPassScope,
}

impl<'a, K, D: 'static> LinkPassPlan<'a, K, D>
where
    K: Clone + Ord,
{
    #[inline]
    pub(crate) fn new(plan: &'a mut LinkPlan<K, D>, scope: LinkPassScope) -> Self {
        Self { plan, scope }
    }

    #[inline]
    fn accepts_key(&self, key: &K) -> bool {
        self.plan
            .module_id(key)
            .and_then(|module_id| self.plan.module_capability(module_id))
            .is_some_and(|capability| self.scope.matches(capability))
    }

    /// Returns the capability scope selected for the current pass.
    #[inline]
    pub const fn scope(&self) -> LinkPassScope {
        self.scope
    }

    /// Returns the canonical root key of the underlying plan.
    #[inline]
    pub fn root_key(&self) -> &K {
        self.plan.root_key()
    }

    /// Returns the canonical root module id of the underlying plan.
    #[inline]
    pub fn root_module(&self) -> LinkModuleId {
        self.plan.root_module()
    }

    /// Iterates over filtered module keys in discovery order.
    pub fn group_order(&self) -> impl Iterator<Item = &K> {
        let scope = self.scope;
        let plan = &*self.plan;
        plan.group_order()
            .iter()
            .copied()
            .filter_map(move |module_id| {
                plan.module_capability(module_id)
                    .is_some_and(|capability| scope.matches(capability))
                    .then(|| plan.module_key(module_id))
                    .flatten()
            })
    }

    /// Iterates over filtered module ids in discovery order.
    pub fn group_order_ids(&self) -> impl Iterator<Item = LinkModuleId> + '_ {
        let scope = self.scope;
        let plan = &*self.plan;
        plan.group_order().iter().copied().filter(move |module_id| {
            plan.module_capability(*module_id)
                .is_some_and(|capability| scope.matches(capability))
        })
    }

    /// Returns whether the filtered view contains `key`.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.accepts_key(key) && self.plan.contains_key(key)
    }

    /// Returns the stable module id for `key`, when visible through this scope.
    #[inline]
    pub fn module_id(&self, key: &K) -> Option<LinkModuleId> {
        self.accepts_key(key)
            .then(|| self.plan.module_id(key))
            .flatten()
    }

    /// Returns the scanned metadata for `module_id` when it is visible through this scope.
    #[inline]
    pub fn entry(&self, module_id: LinkModuleId) -> Option<&ScannedDylib<D>> {
        let capability = self.plan.module_capability(module_id)?;
        if !self.scope.matches(capability) {
            return None;
        }
        self.plan.get(module_id).map(PlannedModule::module)
    }

    /// Returns the scanned metadata for `module_id` mutably when it is visible through this scope.
    #[inline]
    pub fn entry_mut(&mut self, module_id: LinkModuleId) -> Option<&mut ScannedDylib<D>> {
        let capability = self.plan.module_capability(module_id)?;
        if !self.scope.matches(capability) {
            return None;
        }
        self.plan.get_mut(module_id).map(PlannedModule::module_mut)
    }

    /// Iterates over every scanned module visible through this scope.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &ScannedDylib<D>)> {
        let scope = self.scope;
        let plan = &*self.plan;
        plan.iter().filter(move |(key, _)| {
            plan.module_id(key)
                .and_then(|module_id| plan.module_capability(module_id))
                .is_some_and(|capability| scope.matches(capability))
        })
    }

    /// Returns the direct dependencies recorded for `key`, when visible.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<impl Iterator<Item = &K> + '_> {
        if !self.accepts_key(key) {
            return None;
        }
        Some(
            self.plan
                .direct_deps(key)?
                .iter()
                .filter_map(|dep_id| self.plan.module_key(*dep_id)),
        )
    }

    /// Returns the planning capability of `key`, when visible.
    #[inline]
    pub fn module_capability(&self, key: &K) -> Option<ModuleCapability> {
        let module_id = self.module_id(key)?;
        self.plan.module_capability(module_id)
    }

    /// Returns the configured materialization mode of `key`, when visible.
    #[inline]
    pub fn module_materialization(&self, key: &K) -> Option<Materialization> {
        let module_id = self.module_id(key)?;
        self.plan.materialization(module_id)
    }

    /// Selects the materialization mode for `module_id`, when visible.
    #[inline]
    pub fn set_module_materialization(
        &mut self,
        module_id: LinkModuleId,
        mode: Materialization,
    ) -> Option<Materialization> {
        self.plan
            .module_capability(module_id)
            .is_some_and(|capability| self.scope.matches(capability))
            .then(|| self.plan.set_materialization(module_id, mode))
            .flatten()
    }

    /// Returns one section's data, materializing it on demand when needed.
    #[inline]
    pub fn section_data(&mut self, section: LayoutSectionId) -> Result<Option<&AlignedBytes>> {
        let Some(module_id) = self.plan.memory_layout().section_owner(section) else {
            return Ok(None);
        };
        if !self
            .plan
            .module_capability(module_id)
            .is_some_and(|capability| self.scope.matches(capability))
        {
            return Ok(None);
        }
        Ok(Some(self.plan.section_data(section)?))
    }

    /// Returns mutable section data, materializing it on demand when needed.
    #[inline]
    pub fn section_data_mut(
        &mut self,
        section: LayoutSectionId,
    ) -> Result<Option<&mut AlignedBytes>> {
        let Some(module_id) = self.plan.memory_layout().section_owner(section) else {
            return Ok(None);
        };
        if !self
            .plan
            .module_capability(module_id)
            .is_some_and(|capability| self.scope.matches(capability))
        {
            return Ok(None);
        }
        Ok(Some(self.plan.section_data_mut(section)?))
    }

    /// Returns the filtered plan's memory-layout core.
    #[inline]
    pub fn memory_layout(&self) -> &MemoryLayoutPlan {
        self.plan.memory_layout()
    }

    /// Returns the filtered plan's memory-layout core mutably.
    #[inline]
    pub fn memory_layout_mut(&mut self) -> &mut MemoryLayoutPlan {
        self.plan.memory_layout_mut()
    }
}

/// A pass that inspects or rewrites a pre-map global link plan.
pub trait LinkPass<K: Ord, D: 'static> {
    /// Returns the minimum module capability this pass operates on.
    #[inline]
    fn capability_scope(&self) -> LinkPassScope {
        LinkPassScope::Any
    }

    /// Executes the pass over the current plan.
    fn run(&mut self, plan: &mut LinkPassPlan<'_, K, D>) -> Result<()>;
}

impl<K: Ord, D: 'static, F> LinkPass<K, D> for F
where
    F: for<'a> FnMut(&mut LinkPassPlan<'a, K, D>) -> Result<()>,
{
    #[inline]
    fn run(&mut self, plan: &mut LinkPassPlan<'_, K, D>) -> Result<()> {
        (self)(plan)
    }
}

/// An ordered collection of [`LinkPass`]es.
///
/// This is the pass manager used with a discovered [`LinkPlan`] after
/// metadata discovery finishes and before any module is mapped into memory.
pub struct LinkPipeline<'a, K: Ord, D: 'static> {
    passes: Vec<&'a mut dyn LinkPass<K, D>>,
}

impl<'a, K: Ord, D: 'static> Default for LinkPipeline<'a, K, D> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K: Ord, D: 'static> LinkPipeline<'a, K, D> {
    /// Creates an empty pipeline.
    #[inline]
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Appends a pass to the pipeline.
    #[inline]
    pub fn push(&mut self, pass: &'a mut dyn LinkPass<K, D>) -> &mut Self {
        self.passes.push(pass);
        self
    }

    /// Runs the pipeline with caller-supplied query state.
    pub(crate) fn run(&mut self, plan: &mut LinkPlan<K, D>) -> Result<()>
    where
        K: Clone,
    {
        for pass in &mut self.passes {
            let mut scoped = LinkPassPlan::new(plan, pass.capability_scope());
            pass.run(&mut scoped)?;
        }
        Ok(())
    }
}

pub(crate) struct PlannedModule<K, D: 'static> {
    key: K,
    module: ScannedDylib<D>,
    direct_deps: Box<[LinkModuleId]>,
}

struct PendingPlannedModule<K, D: 'static> {
    key: K,
    module: ScannedDylib<D>,
    direct_deps: Box<[K]>,
}

impl<K, D: 'static> PendingPlannedModule<K, D>
where
    K: Ord,
{
    fn resolve(self, module_ids: &BTreeMap<K, LinkModuleId>) -> PlannedModule<K, D> {
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

impl<K, D: 'static> PlannedModule<K, D> {
    #[inline]
    pub(crate) fn new(key: K, module: ScannedDylib<D>, direct_deps: Box<[LinkModuleId]>) -> Self {
        Self {
            key,
            module,
            direct_deps,
        }
    }

    #[inline]
    pub(crate) fn key(&self) -> &K {
        &self.key
    }

    #[inline]
    pub(crate) fn module(&self) -> &ScannedDylib<D> {
        &self.module
    }

    #[inline]
    pub(crate) fn module_mut(&mut self) -> &mut ScannedDylib<D> {
        &mut self.module
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> &[LinkModuleId] {
        &self.direct_deps
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (K, ScannedDylib<D>, Box<[LinkModuleId]>) {
        (self.key, self.module, self.direct_deps)
    }
}

/// A global, pre-map link plan built from metadata discovery.
///
/// This plan owns the discovered logical module graph and accumulates later
/// planning decisions such as physical memory-layout plans or future
/// materialization policies.
pub(crate) struct LinkPlan<K, D: 'static> {
    root: LinkModuleId,
    group_order: Vec<LinkModuleId>,
    module_ids: BTreeMap<K, LinkModuleId>,
    entries: PrimaryMap<LinkModuleId, PlannedModule<K, D>>,
    memory_layout: MemoryLayoutPlan,
}

impl<K, D: 'static> LinkPlan<K, D>
where
    K: Clone + Ord,
{
    #[inline]
    pub(crate) fn new(
        root: K,
        group_order: Vec<K>,
        mut entries: BTreeMap<K, (ScannedDylib<D>, Box<[K]>)>,
    ) -> Self {
        let group_keys = group_order;
        let mut module_ids = BTreeMap::new();
        let mut group_order = Vec::with_capacity(group_keys.len());
        let mut pending_entries = PrimaryMap::default();
        for key in group_keys {
            let (module, direct_deps) = entries
                .remove(&key)
                .expect("scan plan group order referenced a missing discovered module");
            let module_id = pending_entries.push(PendingPlannedModule {
                key: key.clone(),
                module,
                direct_deps,
            });
            let previous = module_ids.insert(key, module_id);
            assert!(
                previous.is_none(),
                "scan plan discovered duplicate module key"
            );
            group_order.push(module_id);
        }

        let root = *module_ids
            .get(&root)
            .expect("scan plan root must exist in discovery order");

        let planned_entries = pending_entries.map_values(|_, pending| pending.resolve(&module_ids));
        assert!(
            entries.is_empty(),
            "scan plan contained modules that were not present in discovery order"
        );

        let memory_layout = MemoryLayoutPlan::seed_from_scanned_modules(
            planned_entries
                .iter()
                .map(|(module_id, entry)| (module_id, entry.module())),
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
    fn root_key(&self) -> &K {
        self.module_key(self.root)
            .expect("planned root module must resolve to a key")
    }

    /// Returns the canonical root module id of the plan.
    #[inline]
    pub(crate) const fn root_module(&self) -> LinkModuleId {
        self.root
    }

    /// Returns the breadth-first module ids discovered from the root.
    #[inline]
    pub(crate) fn group_order(&self) -> &[LinkModuleId] {
        &self.group_order
    }

    pub(crate) fn try_for_each_module(
        &mut self,
        mut f: impl FnMut(&mut Self, LinkModuleId) -> Result<()>,
    ) -> Result<()> {
        let group_len = self.group_order.len();
        for index in 0..group_len {
            let module_id = self.group_order[index];
            f(self, module_id)?;
        }
        Ok(())
    }

    /// Returns whether the plan contains `key`.
    #[inline]
    fn contains_key(&self, key: &K) -> bool {
        self.module_ids.contains_key(key)
    }

    /// Returns the stable module id for `key`.
    #[inline]
    fn module_id(&self, key: &K) -> Option<LinkModuleId> {
        self.module_ids.get(key).copied()
    }

    #[inline]
    fn module_key(&self, module_id: LinkModuleId) -> Option<&K> {
        self.entries.get(module_id).map(PlannedModule::key)
    }

    #[inline]
    fn get(&self, module_id: LinkModuleId) -> Option<&PlannedModule<K, D>> {
        self.entries.get(module_id)
    }

    #[inline]
    fn get_mut(&mut self, module_id: LinkModuleId) -> Option<&mut PlannedModule<K, D>> {
        self.entries.get_mut(module_id)
    }

    /// Returns the canonical direct dependency ids of `key`.
    #[inline]
    fn direct_deps(&self, key: &K) -> Option<&[LinkModuleId]> {
        let module_id = self.module_id(key)?;
        let entry = self.get(module_id)?;
        Some(entry.direct_deps())
    }

    /// Iterates over all modules in the plan.
    #[inline]
    fn iter(&self) -> impl Iterator<Item = (&K, &ScannedDylib<D>)> {
        self.entries
            .iter()
            .map(|(_, entry)| (entry.key(), entry.module()))
    }

    /// Returns the physical memory-layout plan associated with this graph.
    #[inline]
    pub fn memory_layout(&self) -> &MemoryLayoutPlan {
        &self.memory_layout
    }

    /// Returns the physical memory-layout plan mutably.
    #[inline]
    pub fn memory_layout_mut(&mut self) -> &mut MemoryLayoutPlan {
        &mut self.memory_layout
    }

    /// Returns one module's layout view by stable module id.
    #[inline]
    pub(crate) fn module_layout(&self, module_id: LinkModuleId) -> &ModuleLayout {
        self.memory_layout.module(module_id)
    }

    /// Returns one section metadata record by stable section id.
    #[inline]
    pub(crate) fn section_metadata(&self, section: LayoutSectionId) -> &LayoutSectionMetadata {
        self.memory_layout.section_metadata(section)
    }

    #[inline]
    pub(crate) fn module_capability(&self, module_id: LinkModuleId) -> Option<ModuleCapability> {
        self.get(module_id).map(|entry| entry.module().capability())
    }

    #[inline]
    pub(crate) fn materialization(&self, module_id: LinkModuleId) -> Option<Materialization> {
        self.memory_layout.materialization(module_id)
    }

    /// Selects the materialization mode for one module.
    #[inline]
    pub fn set_materialization(
        &mut self,
        module_id: LinkModuleId,
        mode: Materialization,
    ) -> Option<Materialization> {
        self.memory_layout.set_materialization(module_id, mode)
    }

    fn materialize_section_data(
        entries: &mut PrimaryMap<LinkModuleId, PlannedModule<K, D>>,
        memory_layout: &mut MemoryLayoutPlan,
        section: LayoutSectionId,
    ) -> Result<()> {
        if memory_layout.section_data(section).is_some() {
            return Ok(());
        }

        let module_id = memory_layout.section_owner(section).ok_or_else(|| {
            LinkerError::section_data("section data requested for an unowned section")
        })?;
        let entry = entries.get_mut(module_id).ok_or_else(|| {
            LinkerError::section_data("section data requested for a missing planned module")
        })?;
        if !entry.module().capability().has_section_data() {
            return Err(LinkerError::section_data(
                "section data requested for a module without section data",
            )
            .into());
        }

        let scanned_section = memory_layout.section_metadata(section).scanned_section();
        let snapshot = entry
            .module_mut()
            .section_data(scanned_section)?
            .ok_or_else(|| {
                LinkerError::section_data("section data requested for a missing scanned section")
            })?;

        memory_layout.install_section_data(section, snapshot);
        Ok(())
    }

    /// Returns one section's data, materializing it on demand when needed.
    pub fn section_data(&mut self, section: LayoutSectionId) -> Result<&AlignedBytes> {
        let (data, _) = self.section_data_with_layout(section)?;
        Ok(data)
    }

    /// Returns one section's data together with the layout that owns it.
    pub(crate) fn section_data_with_layout(
        &mut self,
        section: LayoutSectionId,
    ) -> Result<(&AlignedBytes, &MemoryLayoutPlan)> {
        let Self {
            entries,
            memory_layout,
            ..
        } = self;
        if memory_layout.section_data(section).is_none() {
            Self::materialize_section_data(entries, memory_layout, section)?;
        }

        let layout = &*memory_layout;
        let data = layout
            .section_data(section)
            .ok_or_else(|| LinkerError::section_data("section data was not materialized"))?;
        Ok((data, layout))
    }

    /// Returns mutable section data, materializing it on demand when needed.
    pub fn section_data_mut(&mut self, section: LayoutSectionId) -> Result<&mut AlignedBytes> {
        let _ = self.section_data(section)?;
        let _ = self.memory_layout.mark_section_data_override(section);
        self.memory_layout
            .section_data_mut(section)
            .ok_or_else(|| LinkerError::section_data("section data was not materialized"))
            .map_err(Into::into)
    }

    pub(crate) fn with_disjoint_section_data_mut<R>(
        &mut self,
        read_a: LayoutSectionId,
        read_b: LayoutSectionId,
        write: LayoutSectionId,
        f: impl FnOnce(&AlignedBytes, &AlignedBytes, &mut AlignedBytes) -> Result<R>,
    ) -> Result<R> {
        if read_a == read_b || read_a == write || read_b == write {
            return Err(LinkerError::section_data(
                "disjoint section data request referenced the same section more than once",
            )
            .into());
        }

        let Self {
            entries,
            memory_layout,
            ..
        } = self;
        for section in [read_a, read_b, write] {
            if memory_layout.section_data(section).is_none() {
                Self::materialize_section_data(entries, memory_layout, section)?;
            }
        }

        let _ = memory_layout.mark_section_data_override(write);
        memory_layout
            .with_disjoint_section_data_mut(read_a, read_b, write, f)
            .ok_or_else(|| {
                LinkerError::section_data("disjoint section data was not materialized")
            })?
    }

    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (
        LinkModuleId,
        Vec<LinkModuleId>,
        PrimaryMap<LinkModuleId, PlannedModule<K, D>>,
        MemoryLayoutPlan,
    ) {
        (
            self.root,
            self.group_order,
            self.entries,
            self.memory_layout,
        )
    }
}
