//! Link-plan transformation passes.

use super::{
    ArenaDescriptor, SectionId,
    layout::{DataAccess, SectionDataAccessRef},
    plan::{LinkPlan, ModuleId},
};
use crate::{
    LinkerError, Result, aligned_bytes::ByteRepr, image::ModuleCapability,
    relocation::RelocationArch,
};
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

mod arena;
mod module;
mod section;
pub use arena::Arena;
pub use module::Module;
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

    #[inline]
    fn checked_module(&self, id: ModuleId) -> Option<Module<'a, S>> {
        self.accepts_module(id).then(|| Module::new(id))
    }

    /// Returns the canonical root key of the underlying plan.
    #[inline]
    pub fn root_key(&self) -> &K {
        self.plan.root_key()
    }

    /// Returns the canonical root module when it is visible through this pass scope.
    #[inline]
    pub fn root(&self) -> Option<Module<'a, S>> {
        self.checked_module(self.plan.root_module())
    }

    /// Returns whether the underlying plan contains `key`.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.plan.contains_key(key)
    }

    /// Returns one planned module by canonical key, when visible through this pass scope.
    #[inline]
    pub fn module(&self, key: &K) -> Option<Module<'a, S>> {
        self.checked_module(self.plan.module_id(key)?)
    }

    /// Iterates over modules visible through this pass scope in discovery order.
    pub fn modules(&self) -> impl Iterator<Item = Module<'a, S>> + '_ {
        self.plan
            .group_order()
            .iter()
            .copied()
            .filter_map(move |id| self.checked_module(id))
    }
}

impl<'a, K, S, Arch> LinkPassPlan<'a, K, S, Arch>
where
    K: Clone + Ord,
    S: SectionDataAccess,
    Arch: RelocationArch,
{
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

    /// Iterates visible entries from one section.
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
    pub fn create_arena(&mut self, arena: ArenaDescriptor) -> Arena<'a> {
        Arena::new(self.plan.memory_layout_mut().create_arena(arena))
    }

    /// Iterates over planned arenas.
    #[inline]
    pub fn arenas(&self) -> impl Iterator<Item = Arena<'a>> + '_ {
        self.plan
            .memory_layout()
            .arena_pairs()
            .map(|(arena, _)| Arena::new(arena))
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
