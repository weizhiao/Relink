use super::{LayoutModuleMaterialization, LayoutSectionArena, LayoutSectionId, MemoryLayoutPlan};
use crate::{
    AlignedBytes, Result,
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
        plan.group_order().filter(move |key| {
            plan.module_id(key)
                .and_then(|module_id| plan.module_capability(module_id))
                .is_some_and(|capability| scope.matches(capability))
        })
    }

    /// Iterates over filtered module ids in discovery order.
    pub fn group_order_ids(&self) -> impl Iterator<Item = LinkModuleId> + '_ {
        let scope = self.scope;
        let plan = &*self.plan;
        plan.group_order_ids()
            .iter()
            .copied()
            .filter(move |module_id| {
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

    /// Returns the scanned metadata for `key` when it is visible through this scope.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&ScannedDylib<D>> {
        self.accepts_key(key).then(|| self.plan.get(key)).flatten()
    }

    /// Returns the scanned metadata for `key` mutably when it is visible through this scope.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut ScannedDylib<D>> {
        if !self.accepts_key(key) {
            return None;
        }
        self.plan.get_mut(key)
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
        self.plan.direct_deps(key)
    }

    /// Returns the planning capability of `key`, when visible.
    #[inline]
    pub fn module_capability(&self, key: &K) -> Option<ModuleCapability> {
        let module_id = self.module_id(key)?;
        self.plan.module_capability(module_id)
    }

    /// Returns the configured materialization mode of `key`, when visible.
    #[inline]
    pub fn module_materialization(&self, key: &K) -> Option<LayoutModuleMaterialization> {
        let module_id = self.module_id(key)?;
        self.plan.module_materialization(module_id)
    }

    /// Selects the materialization mode for `module_id`, when visible.
    #[inline]
    pub fn set_module_materialization(
        &mut self,
        module_id: LinkModuleId,
        mode: LayoutModuleMaterialization,
    ) -> Option<LayoutModuleMaterialization> {
        self.plan
            .module_capability(module_id)
            .is_some_and(|capability| self.scope.matches(capability))
            .then(|| self.plan.set_module_materialization(module_id, mode))
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
pub struct LinkPlan<K, D: 'static> {
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
        for key in &group_keys {
            let next_id = LinkModuleId::new(module_ids.len());
            let previous = module_ids.insert(key.clone(), next_id);
            assert!(
                previous.is_none(),
                "scan plan discovered duplicate module key"
            );
            group_order.push(next_id);
        }

        let root = *module_ids
            .get(&root)
            .expect("scan plan root must exist in discovery order");

        let mut planned_entries = PrimaryMap::default();
        for key in &group_keys {
            let module_id = *module_ids
                .get(key)
                .expect("planned module key must have an assigned id");
            let (module, direct_deps) = entries
                .remove(key)
                .expect("scan plan group order referenced a missing discovered module");
            let direct_deps = direct_deps
                .iter()
                .map(|dep_key| {
                    *module_ids.get(dep_key).unwrap_or_else(|| {
                        panic!("planned module dependency referenced an unknown module key")
                    })
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let inserted_id =
                planned_entries.push(PlannedModule::new(key.clone(), module, direct_deps));
            assert_eq!(
                inserted_id, module_id,
                "planned module ids must be assigned in discovery order"
            );
        }
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
    pub fn root_key(&self) -> &K {
        self.module_key(self.root)
            .expect("planned root module must resolve to a key")
    }

    /// Returns the canonical root module id of the plan.
    #[inline]
    pub const fn root_module(&self) -> LinkModuleId {
        self.root
    }

    /// Returns the breadth-first module order discovered from the root.
    #[inline]
    pub fn group_order(&self) -> impl Iterator<Item = &K> {
        self.group_order
            .iter()
            .filter_map(|module_id| self.module_key(*module_id))
    }

    /// Returns the breadth-first module ids discovered from the root.
    #[inline]
    pub(crate) fn group_order_ids(&self) -> &[LinkModuleId] {
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
    pub fn contains_key(&self, key: &K) -> bool {
        self.module_ids.contains_key(key)
    }

    /// Returns the stable module id for `key`.
    #[inline]
    pub fn module_id(&self, key: &K) -> Option<LinkModuleId> {
        self.module_ids.get(key).copied()
    }

    #[inline]
    pub(crate) fn module_key(&self, module_id: LinkModuleId) -> Option<&K> {
        self.entries.get(module_id).map(PlannedModule::key)
    }

    #[inline]
    fn entry(&self, module_id: LinkModuleId) -> Option<&PlannedModule<K, D>> {
        self.entries.get(module_id)
    }

    #[inline]
    fn entry_mut(&mut self, module_id: LinkModuleId) -> Option<&mut PlannedModule<K, D>> {
        self.entries.get_mut(module_id)
    }

    /// Returns the scanned metadata for `key`.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&ScannedDylib<D>> {
        self.module_id(key)
            .and_then(|module_id| self.entry(module_id))
            .map(PlannedModule::module)
    }

    /// Returns the scanned metadata for `key` mutably.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut ScannedDylib<D>> {
        let module_id = self.module_id(key)?;
        self.entry_mut(module_id).map(PlannedModule::module_mut)
    }

    /// Returns the canonical direct dependency keys of `key`.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<impl Iterator<Item = &K> + '_> {
        let module_id = self.module_id(key)?;
        let entry = self.entry(module_id)?;
        Some(
            entry
                .direct_deps()
                .iter()
                .filter_map(|dep_id| self.module_key(*dep_id)),
        )
    }

    /// Iterates over all modules in the plan.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&K, &ScannedDylib<D>)> {
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

    #[inline]
    pub(crate) fn module_capability(&self, module_id: LinkModuleId) -> Option<ModuleCapability> {
        self.entry(module_id)
            .map(|entry| entry.module().capability())
    }

    #[inline]
    pub(crate) fn scanned_module(&self, module_id: LinkModuleId) -> Option<&ScannedDylib<D>> {
        self.entry(module_id).map(PlannedModule::module)
    }

    #[inline]
    pub(crate) fn module_materialization(
        &self,
        module_id: LinkModuleId,
    ) -> Option<LayoutModuleMaterialization> {
        self.memory_layout.module_materialization(module_id)
    }
}

impl<K, D: 'static> LinkPlan<K, D>
where
    K: Clone + Ord,
{
    /// Selects the materialization mode for one module.
    #[inline]
    pub fn set_module_materialization(
        &mut self,
        module_id: LinkModuleId,
        mode: LayoutModuleMaterialization,
    ) -> Option<LayoutModuleMaterialization> {
        self.memory_layout
            .set_module_materialization(module_id, mode)
    }

    fn materialize_section_data(
        entries: &mut PrimaryMap<LinkModuleId, PlannedModule<K, D>>,
        sections: &mut LayoutSectionArena,
        section: LayoutSectionId,
    ) -> Result<()> {
        if sections.data(section).is_some() {
            return Ok(());
        }

        let module_id = sections
            .owner(section)
            .ok_or_else(|| crate::custom_error("section data requested for an unowned section"))?;
        let entry = entries.get_mut(module_id).ok_or_else(|| {
            crate::custom_error("section data requested for a missing planned module")
        })?;
        if !entry.module().capability().has_section_data() {
            return Err(crate::custom_error(
                "section data requested for a module without section data",
            ));
        }

        let scanned_section = sections
            .get(section)
            .expect("link plan tried to materialize data for a missing section")
            .scanned_section();
        let snapshot = entry
            .module_mut()
            .section_data(scanned_section)?
            .ok_or_else(|| {
                crate::custom_error("section data requested for a missing scanned section")
            })?;

        sections.install_scanned_data(section, snapshot);
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
        if memory_layout.sections().data(section).is_none() {
            Self::materialize_section_data(entries, memory_layout.sections_mut(), section)?;
        }

        let layout = &*memory_layout;
        let data = layout
            .sections()
            .data(section)
            .ok_or_else(|| crate::custom_error("section data was not materialized"))?;
        Ok((data, layout))
    }

    /// Returns mutable section data, materializing it on demand when needed.
    pub fn section_data_mut(&mut self, section: LayoutSectionId) -> Result<&mut AlignedBytes> {
        let _ = self.section_data(section)?;
        let sections = self.memory_layout.sections_mut();
        let _ = sections.mark_data_override(section);
        sections
            .data_mut(section)
            .ok_or_else(|| crate::custom_error("section data was not materialized"))
    }

    #[inline]
    pub(crate) fn finalize_layout(&mut self) -> Result<()> {
        Ok(())
    }

    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (
        LinkModuleId,
        Vec<LinkModuleId>,
        Vec<PlannedModule<K, D>>,
        MemoryLayoutPlan,
    ) {
        (
            self.root,
            self.group_order,
            self.entries.into_values(),
            self.memory_layout,
        )
    }
}
