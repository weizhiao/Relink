use super::{
    layout::{
        LayoutRepairStatus, MemoryLayoutPlan, ModuleLayout, ModuleLayoutRepair,
        ModulePhysicalLayout,
    },
    scan::ScanContextView,
    view::LinkContextView,
};
use crate::image::{LoadedCore, RawDylib, ScannedDylib};
use alloc::boxed::Box;

/// The owner module being resolved for one dependency edge.
pub enum DependencyOwner<'a, D: 'static> {
    Raw(&'a RawDylib<D>),
    Scanned(&'a ScannedDylib<D>),
}

impl<'a, D: 'static> Copy for DependencyOwner<'a, D> {}

impl<'a, D: 'static> Clone for DependencyOwner<'a, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, D: 'static> DependencyOwner<'a, D> {
    /// Returns the owner module as a raw dylib, when available.
    #[inline]
    pub fn raw(&self) -> Option<&'a RawDylib<D>> {
        match self {
            Self::Raw(owner) => Some(owner),
            Self::Scanned(_) => None,
        }
    }

    /// Returns the owner module as scanned metadata, when available.
    #[inline]
    pub fn scanned(&self) -> Option<&'a ScannedDylib<D>> {
        match self {
            Self::Raw(_) => None,
            Self::Scanned(owner) => Some(owner),
        }
    }

    /// Returns the owner module name.
    #[inline]
    pub fn name(&self) -> &'a str {
        match self {
            Self::Raw(owner) => owner.name(),
            Self::Scanned(owner) => owner.name(),
        }
    }

    #[inline]
    fn rpath(&self) -> Option<&'a str> {
        match self {
            Self::Raw(owner) => owner.rpath(),
            Self::Scanned(owner) => owner.rpath(),
        }
    }

    #[inline]
    fn runpath(&self) -> Option<&'a str> {
        match self {
            Self::Raw(owner) => owner.runpath(),
            Self::Scanned(owner) => owner.runpath(),
        }
    }

    #[inline]
    fn interp(&self) -> Option<&'a str> {
        match self {
            Self::Raw(owner) => owner.interp(),
            Self::Scanned(owner) => owner.interp(),
        }
    }

    #[inline]
    fn needed_lib(&self, index: usize) -> Option<&'a str> {
        match self {
            Self::Raw(owner) => owner.needed_libs().get(index).copied(),
            Self::Scanned(owner) => owner.needed_lib(index),
        }
    }
}

/// The dependency-resolution context visible to one request.
pub enum DependencyContext<'a, K, D: 'static> {
    Load(LinkContextView<'a, K, D>),
    Scan(ScanContextView<'a, K, D>),
}

impl<'a, K, D: 'static> Copy for DependencyContext<'a, K, D> {}

impl<'a, K, D: 'static> Clone for DependencyContext<'a, K, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static> DependencyContext<'a, K, D>
where
    K: Ord,
{
    /// Returns the visible linked context, when resolution happens during loading.
    #[inline]
    pub fn load(&self) -> Option<LinkContextView<'a, K, D>> {
        match self {
            Self::Load(context) => Some(*context),
            Self::Scan(_) => None,
        }
    }

    /// Returns the visible scan context, when resolution happens during discovery.
    #[inline]
    pub fn scan(&self) -> Option<ScanContextView<'a, K, D>> {
        match self {
            Self::Load(_) => None,
            Self::Scan(context) => Some(*context),
        }
    }

    /// Returns whether the current context already knows `key`.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        match self {
            Self::Load(context) => context.contains_key(key),
            Self::Scan(context) => context.contains_key(key),
        }
    }

    /// Returns the known direct dependencies for `key`, when available.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        match self {
            Self::Load(context) => context.direct_deps(key),
            Self::Scan(context) => context.direct_deps(key),
        }
    }
}

/// A single dependency-resolution request.
pub struct DependencyRequest<'a, K, D: 'static> {
    owner_key: &'a K,
    owner: DependencyOwner<'a, D>,
    needed_index: usize,
    context: DependencyContext<'a, K, D>,
}

impl<'a, K, D: 'static> DependencyRequest<'a, K, D> {
    #[inline]
    pub(crate) fn new(
        owner_key: &'a K,
        owner: &'a RawDylib<D>,
        needed_index: usize,
        context: LinkContextView<'a, K, D>,
    ) -> Self {
        Self {
            owner_key,
            owner: DependencyOwner::Raw(owner),
            needed_index,
            context: DependencyContext::Load(context),
        }
    }

    #[inline]
    pub(crate) fn new_scanned(
        owner_key: &'a K,
        owner: &'a ScannedDylib<D>,
        needed_index: usize,
        context: ScanContextView<'a, K, D>,
    ) -> Self {
        Self {
            owner_key,
            owner: DependencyOwner::Scanned(owner),
            needed_index,
            context: DependencyContext::Scan(context),
        }
    }

    /// Returns the key of the owner module.
    #[inline]
    pub fn owner_key(&self) -> &'a K {
        self.owner_key
    }

    /// Returns the owner module.
    #[inline]
    pub fn owner(&self) -> DependencyOwner<'a, D> {
        self.owner
    }

    /// Returns the owner module name.
    #[inline]
    pub fn owner_name(&self) -> &'a str {
        self.owner.name()
    }

    /// Returns the current `DT_NEEDED` string.
    #[inline]
    pub fn needed(&self) -> &'a str {
        self.owner
            .needed_lib(self.needed_index)
            .expect("DT_NEEDED index out of bounds")
    }

    /// Returns the index of the current `DT_NEEDED` entry.
    #[inline]
    pub fn needed_index(&self) -> usize {
        self.needed_index
    }

    /// Returns the owner's `DT_RPATH`.
    #[inline]
    pub fn rpath(&self) -> Option<&'a str> {
        self.owner.rpath()
    }

    /// Returns the owner's `DT_RUNPATH`.
    #[inline]
    pub fn runpath(&self) -> Option<&'a str> {
        self.owner.runpath()
    }

    /// Returns the owner's `PT_INTERP`.
    #[inline]
    pub fn interp(&self) -> Option<&'a str> {
        self.owner.interp()
    }

    /// Returns the currently visible dependency-resolution context.
    #[inline]
    pub fn context(&self) -> DependencyContext<'a, K, D> {
        self.context
    }
}

/// A single relocation request for a newly mapped module.
pub struct RelocationRequest<'a, K, D: 'static> {
    key: &'a K,
    raw: RawDylib<D>,
    context: LinkContextView<'a, K, D>,
    scope_order: &'a [K],
    scope: Box<[LoadedCore<D>]>,
    memory_layout: Option<&'a MemoryLayoutPlan<K>>,
}

impl<'a, K, D: 'static> RelocationRequest<'a, K, D> {
    #[inline]
    pub(crate) fn new(
        key: &'a K,
        raw: RawDylib<D>,
        context: LinkContextView<'a, K, D>,
        scope_order: &'a [K],
        scope: Box<[LoadedCore<D>]>,
        memory_layout: Option<&'a MemoryLayoutPlan<K>>,
    ) -> Self {
        Self {
            key,
            raw,
            context,
            scope_order,
            scope,
            memory_layout,
        }
    }

    /// Returns the key selected for the module being relocated.
    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    /// Returns the raw module being relocated.
    #[inline]
    pub fn raw(&self) -> &RawDylib<D> {
        &self.raw
    }

    /// Returns the currently visible linked modules.
    #[inline]
    pub fn context(&self) -> LinkContextView<'a, K, D> {
        self.context
    }

    /// Returns the planned relocation-scope order for the current module.
    #[inline]
    pub fn scope_order(&self) -> &'a [K] {
        self.scope_order
    }

    /// Returns the currently planned relocation scope, including pending-group
    /// placeholders that are not yet visible through the context view.
    #[inline]
    pub fn scope(&self) -> &[LoadedCore<D>] {
        &self.scope
    }

    /// Returns the graph-level memory-layout core, when relocation comes from scan planning.
    #[inline]
    pub fn memory_layout(&self) -> Option<&'a MemoryLayoutPlan<K>>
    where
        K: Ord,
    {
        self.memory_layout
    }

    /// Returns the logical section view for the current module, when planned.
    #[inline]
    pub fn module_layout(&self) -> Option<&'a ModuleLayout>
    where
        K: Ord,
    {
        self.memory_layout
            .and_then(|layout| layout.module(self.key))
    }

    /// Returns the physical arena slices owned by the current module.
    #[inline]
    pub fn module_physical_layout(&self) -> Option<&'a ModulePhysicalLayout>
    where
        K: Ord,
    {
        self.memory_layout
            .and_then(|layout| layout.module_physical_layout(self.key))
    }

    /// Returns the built-in reorder-repair worklist for the current module.
    #[inline]
    pub fn module_repair(&self) -> Option<&'a ModuleLayoutRepair>
    where
        K: Ord,
    {
        self.memory_layout
            .and_then(|layout| layout.module_repair(self.key))
    }

    /// Returns whether the current module can be safely reordered and repaired.
    #[inline]
    pub fn repair_status(&self) -> LayoutRepairStatus
    where
        K: Ord,
    {
        self.memory_layout
            .map(|layout| layout.repair_status(self.key))
            .unwrap_or(LayoutRepairStatus::NotNeeded)
    }

    /// Consumes the request and returns the raw module being relocated.
    #[inline]
    pub fn into_raw(self) -> RawDylib<D> {
        self.raw
    }
}
