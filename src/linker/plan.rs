use super::{
    Arena, ArenaId, ArenaUsage, Materialization, ModuleLayout, SectionId, SectionMetadata,
    SectionPlacement, layout::MemoryLayoutPlan,
};
use crate::{
    AlignedBytes, LinkerError, Result,
    entity::{PrimaryMap, entity_ref},
    image::{ModuleCapability, ScannedDylib, ScannedSectionId},
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;

/// A stable id for one planned module stored inside a [`LinkPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleId(usize);
entity_ref!(ModuleId);

/// The minimum module capability required by one planning pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PassScope {
    /// Run over every scanned module, including opaque modules.
    #[default]
    Any,
    /// Run only over modules that expose section metadata/data.
    SectionData,
    /// Run only over modules that support section-reorder repair.
    SectionReorderable,
}

impl PassScope {
    #[inline]
    pub(crate) const fn matches(self, capability: ModuleCapability) -> bool {
        match self {
            Self::Any => true,
            Self::SectionData => !matches!(capability, ModuleCapability::Opaque),
            Self::SectionReorderable => matches!(capability, ModuleCapability::SectionReorderable),
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Type-level scope marker for [`LinkPassPlan`].
pub trait PassScopeMode: sealed::Sealed {
    /// Runtime counterpart of this type-level scope.
    const SCOPE: PassScope;
}

/// Scope marker for passes that may inspect every scanned module.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnyPass;

/// Scope marker for passes that require section metadata/data.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataPass;

/// Scope marker for passes that require section-reorder repair inputs.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReorderPass;

impl sealed::Sealed for AnyPass {}
impl sealed::Sealed for DataPass {}
impl sealed::Sealed for ReorderPass {}

impl PassScopeMode for AnyPass {
    const SCOPE: PassScope = PassScope::Any;
}

impl PassScopeMode for DataPass {
    const SCOPE: PassScope = PassScope::SectionData;
}

impl PassScopeMode for ReorderPass {
    const SCOPE: PassScope = PassScope::SectionReorderable;
}

/// Scope markers that guarantee section metadata/data access.
pub trait DataAccess: PassScopeMode {}

impl DataAccess for DataPass {}
impl DataAccess for ReorderPass {}

/// Scope markers that guarantee section-reorder repair inputs.
pub trait ReorderAccess: DataAccess {}

impl ReorderAccess for ReorderPass {}

/// A mutable planning handle passed to one link pass.
///
/// Graph queries expose the canonical plan. Scope-sensitive APIs such as
/// materialization updates and section-data access enforce `S`.
pub struct LinkPassPlan<'a, K, D: 'static, S = AnyPass>
where
    S: PassScopeMode,
{
    plan: &'a mut LinkPlan<K, D>,
    scope: PhantomData<fn() -> S>,
}

impl<'a, K, D: 'static, S> LinkPassPlan<'a, K, D, S>
where
    K: Clone + Ord,
    S: PassScopeMode,
{
    #[inline]
    fn new(plan: &'a mut LinkPlan<K, D>) -> Self {
        Self {
            plan,
            scope: PhantomData,
        }
    }

    #[inline]
    fn accepts_module(&self, id: ModuleId) -> bool {
        self.plan
            .module_capability(id)
            .is_some_and(|capability| S::SCOPE.matches(capability))
    }

    #[inline]
    fn accepts_section(&self, section: SectionId) -> bool {
        self.plan
            .section_owner(section)
            .is_some_and(|id| self.accepts_module(id))
    }

    #[inline]
    fn visible_section(&self, section: SectionId) -> Option<SectionId> {
        self.accepts_section(section).then_some(section)
    }

    /// Returns the capability scope selected for the current pass.
    #[inline]
    pub const fn scope(&self) -> PassScope {
        S::SCOPE
    }

    /// Returns the canonical root key of the underlying plan.
    #[inline]
    pub fn root_key(&self) -> &K {
        self.plan.root_key()
    }

    /// Returns the canonical root module id of the underlying plan.
    #[inline]
    pub fn root(&self) -> ModuleId {
        self.plan.root_module()
    }

    /// Iterates over all module ids in discovery order.
    pub fn group_order(&self) -> impl Iterator<Item = ModuleId> + '_ {
        self.plan.group_order().iter().copied()
    }

    /// Returns whether the underlying plan contains `key`.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.plan.contains_key(key)
    }

    /// Returns the stable module id for `key`.
    #[inline]
    pub fn module_id(&self, key: &K) -> Option<ModuleId> {
        self.plan.module_id(key)
    }

    /// Returns the canonical key for `id`.
    #[inline]
    pub fn module_key(&self, id: ModuleId) -> Option<&K> {
        self.plan.module_key(id)
    }

    /// Returns the scanned metadata for `id`.
    #[inline]
    pub fn get(&self, id: ModuleId) -> Option<&PlannedModule<K, D>> {
        self.plan.get(id)
    }

    /// Returns the scanned metadata for `id` mutably.
    #[inline]
    pub fn get_mut(&mut self, id: ModuleId) -> Option<&mut PlannedModule<K, D>> {
        self.plan.get_mut(id)
    }

    /// Iterates over every planned module id, key, and scanned module.
    pub fn entries(&self) -> impl Iterator<Item = (ModuleId, &K, &ScannedDylib<D>)> {
        self.plan
            .entries
            .iter()
            .map(|(id, entry)| (id, entry.key(), entry.module()))
    }

    /// Returns direct dependency module ids recorded for `id`.
    #[inline]
    pub fn direct_deps(&self, id: ModuleId) -> Option<impl Iterator<Item = ModuleId> + '_> {
        Some(self.plan.get(id)?.direct_deps().iter().copied())
    }

    /// Returns the planning capability of `id`.
    #[inline]
    pub fn capability(&self, id: ModuleId) -> Option<ModuleCapability> {
        self.plan.module_capability(id)
    }

    /// Returns the configured materialization mode of `id`.
    #[inline]
    pub fn materialization(&self, id: ModuleId) -> Option<Materialization> {
        self.plan.materialization(id)
    }

    /// Selects the materialization mode for `id`, when the module is
    /// visible through this pass scope.
    #[inline]
    pub fn set_materialization(
        &mut self,
        id: ModuleId,
        mode: Materialization,
    ) -> Option<Materialization> {
        self.accepts_module(id)
            .then(|| self.plan.set_materialization(id, mode))
            .flatten()
    }
}

impl<'a, K, D: 'static, S> LinkPassPlan<'a, K, D, S>
where
    K: Clone + Ord,
    S: DataAccess,
{
    /// Returns the planned layout for one visible module.
    #[inline]
    pub fn layout(&self, id: ModuleId) -> Option<&ModuleLayout> {
        self.accepts_module(id).then(|| self.plan.module_layout(id))
    }

    /// Iterates over module layouts visible through this pass scope.
    pub fn layouts(&self) -> impl Iterator<Item = (ModuleId, &ModuleLayout)> + '_ {
        self.plan
            .memory_layout()
            .modules()
            .filter(move |(id, _)| self.accepts_module(*id))
    }

    /// Returns the section id for one scanned section inside one visible module.
    #[inline]
    pub fn section(
        &self,
        module_id: ModuleId,
        id: impl Into<ScannedSectionId>,
    ) -> Option<SectionId> {
        self.accepts_module(module_id)
            .then(|| self.plan.module_section_id(module_id, id))
            .flatten()
    }

    /// Iterates over section metadata records owned by modules visible through this pass scope.
    pub fn sections(&self) -> impl Iterator<Item = (SectionId, &SectionMetadata)> + '_ {
        self.plan
            .memory_layout()
            .sections()
            .filter(move |(section, _)| self.accepts_section(*section))
    }

    /// Returns the visible owner module of `section`.
    #[inline]
    pub fn owner(&self, section: SectionId) -> Option<ModuleId> {
        let owner = self.plan.section_owner(section)?;
        self.accepts_module(owner).then_some(owner)
    }

    /// Returns one metadata record for a section owned by a visible module.
    #[inline]
    pub fn metadata(&self, section: SectionId) -> Option<&SectionMetadata> {
        self.visible_section(section)
            .map(|section| self.plan.section_metadata(section))
    }

    /// Returns one section's data, materializing it on demand when its owner is
    /// visible through this pass scope.
    #[inline]
    pub fn data(&mut self, section: SectionId) -> Result<Option<&AlignedBytes>> {
        self.visible_section(section)
            .map(|section| self.plan.section_data(section))
            .transpose()
    }

    /// Returns mutable section data, materializing it on demand when its owner
    /// is visible through this pass scope.
    #[inline]
    pub fn data_mut(&mut self, section: SectionId) -> Result<Option<&mut AlignedBytes>> {
        self.visible_section(section)
            .map(|section| self.plan.section_data_mut(section))
            .transpose()
    }
}

impl<'a, K, D: 'static, S> LinkPassPlan<'a, K, D, S>
where
    K: Clone + Ord,
    S: ReorderAccess,
{
    /// Creates one arena for section-region materialization.
    #[inline]
    pub fn create_arena(&mut self, arena: Arena) -> ArenaId {
        self.plan.memory_layout_mut().create_arena(arena)
    }

    /// Returns all planned arenas.
    #[inline]
    pub fn arenas(&self) -> &[Arena] {
        self.plan.memory_layout().arenas()
    }

    /// Iterates over planned arenas together with their stable arena ids.
    #[inline]
    pub fn arena_pairs(&self) -> impl Iterator<Item = (ArenaId, &Arena)> {
        self.plan.memory_layout().arena_pairs()
    }

    /// Returns one arena descriptor by arena id.
    #[inline]
    pub fn arena(&self, arena: ArenaId) -> &Arena {
        self.plan.memory_layout().arena(arena)
    }

    /// Returns one arena's derived usage summary.
    #[inline]
    pub fn usage(&self, arena: ArenaId) -> ArenaUsage {
        self.plan.memory_layout().usage(arena)
    }

    /// Returns the arena placement for one visible section.
    #[inline]
    pub fn placement(&self, section: SectionId) -> Option<SectionPlacement> {
        self.visible_section(section)
            .and_then(|section| self.plan.placement(section))
    }

    /// Assigns a visible section to an arena.
    #[inline]
    pub fn assign(&mut self, section: SectionId, arena: ArenaId, offset: usize) -> bool {
        self.visible_section(section)
            .is_some_and(|section| self.plan.memory_layout_mut().assign(section, arena, offset))
    }

    /// Assigns a visible section to an arena at the next aligned offset.
    #[inline]
    pub fn assign_next(&mut self, section: SectionId, arena: ArenaId) -> bool {
        self.visible_section(section)
            .is_some_and(|section| self.plan.memory_layout_mut().assign_next(section, arena))
    }

    /// Clears the arena assignment for one visible section.
    #[inline]
    pub fn clear_section(&mut self, section: SectionId) -> Option<SectionPlacement> {
        self.visible_section(section)
            .and_then(|section| self.plan.memory_layout_mut().clear_section(section))
    }
}

/// A pass that inspects or rewrites a pre-map global link plan.
pub trait LinkPass<K: Clone + Ord, D: 'static, S = AnyPass>
where
    S: PassScopeMode,
{
    /// Executes the pass over the current plan.
    fn run(&mut self, plan: &mut LinkPassPlan<'_, K, D, S>) -> Result<()>;
}

impl<K, D: 'static, S, F> LinkPass<K, D, S> for F
where
    K: Clone + Ord,
    S: PassScopeMode,
    F: for<'a> FnMut(&mut LinkPassPlan<'a, K, D, S>) -> Result<()>,
{
    #[inline]
    fn run(&mut self, plan: &mut LinkPassPlan<'_, K, D, S>) -> Result<()> {
        (self)(plan)
    }
}

type PipelinePass<'a, K, D> = Box<dyn FnMut(&mut LinkPlan<K, D>) -> Result<()> + 'a>;

/// An ordered collection of [`LinkPass`]es.
///
/// This is the pass manager used with a discovered [`LinkPlan`] after
/// metadata discovery finishes and before any module is mapped into memory.
pub struct LinkPipeline<'a, K: Clone + Ord, D: 'static> {
    passes: Vec<PipelinePass<'a, K, D>>,
}

impl<'a, K: Clone + Ord, D: 'static> Default for LinkPipeline<'a, K, D> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K: Clone + Ord, D: 'static> LinkPipeline<'a, K, D> {
    /// Creates an empty pipeline.
    #[inline]
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Appends a pass to the pipeline.
    #[inline]
    pub fn push<P>(&mut self, pass: P) -> &mut Self
    where
        P: LinkPass<K, D, AnyPass> + 'a,
    {
        self.push_scoped::<AnyPass, P>(pass)
    }

    /// Appends a pass that requires a specific type-level capability scope.
    #[inline]
    pub fn push_scoped<S, P>(&mut self, mut pass: P) -> &mut Self
    where
        S: PassScopeMode + 'a,
        P: LinkPass<K, D, S> + 'a,
    {
        self.passes.push(Box::new(move |plan| {
            let mut scoped = LinkPassPlan::<_, _, S>::new(plan);
            pass.run(&mut scoped)
        }));
        self
    }

    /// Runs the pipeline with caller-supplied query state.
    pub(crate) fn run(&mut self, plan: &mut LinkPlan<K, D>) -> Result<()> {
        for pass in &mut self.passes {
            pass(plan)?;
        }
        Ok(())
    }
}

pub struct PlannedModule<K, D: 'static> {
    key: K,
    module: ScannedDylib<D>,
    direct_deps: Box<[ModuleId]>,
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
    fn resolve(self, module_ids: &BTreeMap<K, ModuleId>) -> PlannedModule<K, D> {
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
    pub(crate) fn new(key: K, module: ScannedDylib<D>, direct_deps: Box<[ModuleId]>) -> Self {
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
    pub fn module(&self) -> &ScannedDylib<D> {
        &self.module
    }

    #[inline]
    pub fn module_mut(&mut self) -> &mut ScannedDylib<D> {
        &mut self.module
    }

    #[inline]
    pub fn direct_deps(&self) -> &[ModuleId] {
        &self.direct_deps
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (K, ScannedDylib<D>, Box<[ModuleId]>) {
        (self.key, self.module, self.direct_deps)
    }
}

type LinkPlanParts<K, D> = (
    ModuleId,
    Vec<ModuleId>,
    PrimaryMap<ModuleId, PlannedModule<K, D>>,
    MemoryLayoutPlan,
);

/// A global, pre-map link plan built from metadata discovery.
///
/// This plan owns the discovered logical module graph and accumulates later
/// planning decisions such as physical memory-layout plans or future
/// materialization policies.
pub(crate) struct LinkPlan<K, D: 'static> {
    root: ModuleId,
    group_order: Vec<ModuleId>,
    module_ids: BTreeMap<K, ModuleId>,
    entries: PrimaryMap<ModuleId, PlannedModule<K, D>>,
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
    fn root_key(&self) -> &K {
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
    fn contains_key(&self, key: &K) -> bool {
        self.module_ids.contains_key(key)
    }

    /// Returns the stable module id for `key`.
    #[inline]
    fn module_id(&self, key: &K) -> Option<ModuleId> {
        self.module_ids.get(key).copied()
    }

    #[inline]
    fn module_key(&self, id: ModuleId) -> Option<&K> {
        self.entries.get(id).map(PlannedModule::key)
    }

    #[inline]
    fn get(&self, id: ModuleId) -> Option<&PlannedModule<K, D>> {
        self.entries.get(id)
    }

    #[inline]
    fn get_mut(&mut self, id: ModuleId) -> Option<&mut PlannedModule<K, D>> {
        self.entries.get_mut(id)
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

    fn materialize_section_data(&mut self, section: SectionId) -> Result<()> {
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

    /// Returns one section's data, materializing it on demand when needed.
    pub(crate) fn section_data(&mut self, section: SectionId) -> Result<&AlignedBytes> {
        let (data, _) = self.section_data_with_layout(section)?;
        Ok(data)
    }

    /// Returns one section's data together with the layout that owns it.
    pub(in crate::linker) fn section_data_with_layout(
        &mut self,
        section: SectionId,
    ) -> Result<(&AlignedBytes, &MemoryLayoutPlan)> {
        self.materialize_section_data(section)?;
        let plan = &self.memory_layout;
        let data = plan
            .data(section)
            .ok_or_else(|| LinkerError::section_data("section data was not materialized"))?;
        Ok((data, plan))
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

    pub(crate) fn with_disjoint_section_data_mut<R>(
        &mut self,
        read_a: SectionId,
        read_b: SectionId,
        write: SectionId,
        f: impl FnOnce(&AlignedBytes, &AlignedBytes, &mut AlignedBytes) -> Result<R>,
    ) -> Result<R> {
        if read_a == read_b || read_a == write || read_b == write {
            return Err(LinkerError::section_data(
                "disjoint section data request referenced the same section more than once",
            )
            .into());
        }

        for section in [read_a, read_b, write] {
            self.materialize_section_data(section)?;
        }

        self.memory_layout.mark_section_data_override(write);
        self.memory_layout
            .with_disjoint_section_data_mut(read_a, read_b, write, f)
            .ok_or_else(|| {
                LinkerError::section_data("disjoint section data was not materialized")
            })?
    }

    #[inline]
    pub(in crate::linker) fn into_parts(self) -> LinkPlanParts<K, D> {
        (
            self.root,
            self.group_order,
            self.entries,
            self.memory_layout,
        )
    }
}
