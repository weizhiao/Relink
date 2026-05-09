//! Link-plan transformation passes.

use super::{
    Arena, ArenaId, ArenaUsage, Materialization, ModuleLayout, SectionId,
    layout::{DataAccess, SectionDataAccessRef},
    plan::{LinkPlan, ModuleId, PlannedModule},
};
use crate::{
    LinkerError, Result,
    aligned_bytes::ByteRepr,
    image::{ModuleCapability, ScannedDynamic, ScannedSectionId},
    relocation::RelocationArch,
};
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

mod section;
pub use section::Section;

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
pub trait SectionDataAccess: PassScopeMode {}

impl SectionDataAccess for DataPass {}
impl SectionDataAccess for ReorderPass {}

/// Scope markers that guarantee section-reorder repair inputs.
pub trait ReorderAccess: SectionDataAccess {}

impl ReorderAccess for ReorderPass {}

/// A mutable planning handle passed to one link pass.
///
/// Graph queries expose the canonical plan. Scope-sensitive APIs such as
/// materialization updates and section-data access enforce `S`.
pub struct LinkPassPlan<'a, K, S = AnyPass, Arch: RelocationArch = crate::arch::NativeArch>
where
    S: PassScopeMode,
{
    plan: &'a mut LinkPlan<K, Arch>,
    scope: PhantomData<fn() -> S>,
}

impl<'a, K, S, Arch> LinkPassPlan<'a, K, S, Arch>
where
    K: Clone + Ord,
    S: PassScopeMode,
    Arch: RelocationArch,
{
    #[inline]
    fn new(plan: &'a mut LinkPlan<K, Arch>) -> Self {
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
    pub fn get(&self, id: ModuleId) -> Option<&PlannedModule<K, Arch>> {
        self.plan.get(id)
    }

    /// Returns the scanned metadata for `id` mutably.
    #[inline]
    pub fn get_mut(&mut self, id: ModuleId) -> Option<&mut PlannedModule<K, Arch>> {
        self.plan.get_mut(id)
    }

    /// Iterates over every planned module id, key, and scanned module.
    pub fn entries(&self) -> impl Iterator<Item = (ModuleId, &K, &ScannedDynamic<Arch::Layout>)> {
        self.plan
            .entries()
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

impl<'a, K, S, Arch> LinkPassPlan<'a, K, S, Arch>
where
    K: Clone + Ord,
    S: SectionDataAccess,
    Arch: RelocationArch,
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

    /// Returns one checked section handle for a scanned section inside one visible module.
    #[inline]
    pub fn section(
        &self,
        module_id: ModuleId,
        id: impl Into<ScannedSectionId>,
    ) -> Option<Section<'a, S>> {
        let section = self.plan.module_section_id(module_id, id)?;
        self.checked_section(section)
    }

    #[inline]
    fn checked_section(&self, id: SectionId) -> Option<Section<'a, S>> {
        self.accepts_section(id).then(|| Section::new(id))
    }

    /// Iterates over sections visible through this pass scope.
    pub fn sections(&self) -> impl Iterator<Item = Section<'a, S>> + '_ {
        self.plan
            .memory_layout()
            .sections()
            .filter_map(move |(section, _)| self.checked_section(section))
    }

    /// Iterates visible entries from one section without exposing the layout
    /// internals used to materialize the section.
    #[inline]
    pub fn for_each_section_data<T, P>(
        &mut self,
        section: Section<'a, S>,
        mut prepare: impl FnMut(&T, &Self) -> Result<Option<P>>,
        mut apply: impl FnMut(&mut Self, usize, P) -> Result<()>,
    ) -> Result<()>
    where
        T: ByteRepr,
    {
        let section = section.id();

        self.plan.materialize_section_data(section)?;
        let entry_count = {
            let data =
                self.plan.memory_layout().data(section).ok_or_else(|| {
                    LinkerError::section_data("section data was not materialized")
                })?;
            data.try_cast_slice::<T>()
                .ok_or_else(|| {
                    LinkerError::section_data(
                        "section data bytes do not match requested entry type",
                    )
                })?
                .len()
        };

        for index in 0..entry_count {
            let prepared = {
                let data = self.plan.memory_layout().data(section).ok_or_else(|| {
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
                prepare(entry, &*self)?
            };
            if let Some(prepared) = prepared {
                apply(self, index, prepared)?;
            }
        }

        Ok(())
    }

    /// Returns multiple visible sections' data together, materializing them on
    /// demand when every owner is visible through this pass scope.
    #[inline]
    pub fn with_disjoint_section_data<const N: usize, R>(
        &mut self,
        accesses: [(Section<'a, S>, DataAccess); N],
        f: impl FnOnce([SectionDataAccessRef<'_>; N]) -> Result<R>,
    ) -> Result<R> {
        let accesses = accesses.map(|(section, access)| (section.id(), access));
        self.plan.with_disjoint_section_data(accesses, f)
    }
}

impl<'a, K, S, Arch> LinkPassPlan<'a, K, S, Arch>
where
    K: Clone + Ord,
    S: ReorderAccess,
    Arch: RelocationArch,
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
}

/// A pass that inspects or rewrites a pre-map global link plan.
pub trait LinkPass<K: Clone + Ord, S = AnyPass, Arch: RelocationArch = crate::arch::NativeArch>
where
    S: PassScopeMode,
{
    /// Executes the pass over the current plan.
    fn run(&mut self, plan: &mut LinkPassPlan<'_, K, S, Arch>) -> Result<()>;
}

type PipelinePass<'a, K, Arch> = Box<dyn FnMut(&mut LinkPlan<K, Arch>) -> Result<()> + 'a>;

/// An ordered collection of [`LinkPass`]es.
///
/// This is the pass manager used with a discovered link plan after metadata
/// discovery finishes and before any module is mapped into memory.
pub struct LinkPipeline<'a, K: Clone + Ord, Arch: RelocationArch = crate::arch::NativeArch> {
    passes: Vec<PipelinePass<'a, K, Arch>>,
}

impl<'a, K, Arch> Default for LinkPipeline<'a, K, Arch>
where
    K: Clone + Ord,
    Arch: RelocationArch,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K, Arch> LinkPipeline<'a, K, Arch>
where
    K: Clone + Ord,
    Arch: RelocationArch,
{
    /// Creates an empty pipeline.
    #[inline]
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Appends a pass to the pipeline.
    #[inline]
    pub fn push<S, P>(&mut self, mut pass: P) -> &mut Self
    where
        S: PassScopeMode + 'a,
        P: LinkPass<K, S, Arch> + 'a,
    {
        self.passes.push(Box::new(move |plan| {
            let mut scoped = LinkPassPlan::<_, S, Arch>::new(plan);
            pass.run(&mut scoped)
        }));
        self
    }

    /// Runs the pipeline with caller-supplied query state.
    pub(crate) fn run(&mut self, plan: &mut LinkPlan<K, Arch>) -> Result<()> {
        for pass in &mut self.passes {
            pass(plan)?;
        }
        Ok(())
    }
}
