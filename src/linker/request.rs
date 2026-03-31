use super::view::LinkContextView;
use crate::image::RawDylib;
use alloc::vec::Vec;

/// A single dependency-resolution request.
pub struct DependencyRequest<'a, K, D: 'static> {
    owner_key: &'a K,
    owner: &'a RawDylib<D>,
    needed_index: usize,
    context: LinkContextView<'a, K, D>,
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
            owner,
            needed_index,
            context,
        }
    }

    /// Returns the key of the owner module.
    #[inline]
    pub fn owner_key(&self) -> &'a K {
        self.owner_key
    }

    /// Returns the owner module.
    #[inline]
    pub fn owner(&self) -> &'a RawDylib<D> {
        self.owner
    }

    /// Returns the current `DT_NEEDED` string.
    #[inline]
    pub fn needed(&self) -> &'a str {
        self.owner.needed_libs()[self.needed_index]
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

    /// Returns the currently visible linked modules.
    #[inline]
    pub fn context(&self) -> LinkContextView<'a, K, D> {
        self.context
    }
}

/// A single relocation request for a newly mapped module.
pub struct RelocationRequest<'a, K, D: 'static> {
    key: &'a K,
    raw: RawDylib<D>,
    context: LinkContextView<'a, K, D>,
    scope_order: &'a [K],
}

impl<'a, K, D: 'static> RelocationRequest<'a, K, D> {
    #[inline]
    pub(crate) fn new(
        key: &'a K,
        raw: RawDylib<D>,
        context: LinkContextView<'a, K, D>,
        scope_order: &'a [K],
    ) -> Self {
        Self {
            key,
            raw,
            context,
            scope_order,
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

    /// Builds the currently visible relocation scope in planned order.
    pub fn build_scope(&self) -> Vec<crate::image::LoadedCore<D>>
    where
        K: Ord,
    {
        self.scope_order
            .iter()
            .filter_map(|key| self.context.get(key).cloned())
            .collect()
    }

    /// Consumes the request and returns all relocation inputs.
    #[inline]
    pub fn into_parts(self) -> (&'a K, RawDylib<D>, LinkContextView<'a, K, D>, &'a [K]) {
        (self.key, self.raw, self.context, self.scope_order)
    }
}
