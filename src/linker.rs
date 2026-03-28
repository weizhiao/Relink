//! Explicit linking and dependency-resolution primitives.
//!
//! This module provides building blocks for callers that want to resolve
//! `DT_NEEDED` edges without hard-coding a process-global loader policy.
//! `elf_loader` stays responsible for mapping and local relocation, while
//! callers decide how dependencies are discovered and how search scopes are
//! assembled.

use crate::{
    Result, custom_error,
    image::{LoadedCore, RawDylib},
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    vec::Vec,
};
use core::mem;

/// A module chosen by a loader or dependency resolver.
pub enum ResolvedModule<K, D: 'static> {
    /// Reuses a module that is already present in the current context.
    ///
    /// Resolvers can return this after consulting [`DependencyRequest::context`]
    /// when they want cache-first behavior.
    Existing(K),
    /// Introduces a newly mapped but not yet relocated shared object.
    Raw(K, RawDylib<D>),
    /// Introduces a dependency that is already relocated and ready to use.
    Loaded(K, LoadedCore<D>),
}

impl<K, D> ResolvedModule<K, D> {
    /// Creates a raw module result.
    #[inline]
    pub fn new_raw(key: K, dylib: RawDylib<D>) -> Self {
        Self::Raw(key, dylib)
    }

    /// Creates an already-loaded module result.
    #[inline]
    pub fn new_loaded(key: K, dylib: LoadedCore<D>) -> Self {
        Self::Loaded(key, dylib)
    }

    /// Reuses an existing key from the current context.
    #[inline]
    pub fn existing(key: K) -> Self {
        Self::Existing(key)
    }

    /// Returns the selected key.
    #[inline]
    pub fn key(&self) -> &K {
        match self {
            Self::Existing(key) | Self::Raw(key, _) | Self::Loaded(key, _) => key,
        }
    }
}

/// Resolver callbacks for root modules and `DT_NEEDED` edges.
///
/// A resolver turns a caller-defined key into a concrete root module, and can
/// also resolve dependency requests produced while linking that root.
///
/// The root-loading and dependency-resolution steps are kept together because
/// they usually share the same cache lookup, canonicalization, and probing
/// logic.
///
/// A root load turns a caller-defined key into a concrete module selected for the
/// current [`LinkContext`]. It may canonicalize the key by returning a
/// different [`ResolvedModule::key()`] than the requested one.
pub trait ModuleResolver<K, D: 'static> {
    /// Loads one module entry point identified by `key`.
    fn load(&mut self, key: &K) -> Result<ResolvedModule<K, D>>;
    fn resolve(
        &mut self,
        req: &DependencyRequest<'_, K, D>,
    ) -> Result<Option<ResolvedModule<K, D>>>;
}

/// Relocation callbacks for newly mapped modules discovered during `load()`.
///
/// A relocator receives each raw module after dependency resolution has fixed
/// its direct dependency set and established the currently visible load scope.
///
/// For ad-hoc use, any closure `FnMut(RelocationRequest) -> Result<LoadedCore>`
/// also implements this trait.
pub trait ModuleRelocator<K, D: 'static> {
    /// Relocates one newly mapped module into its ready-to-use loaded form.
    fn relocate(&mut self, req: RelocationRequest<'_, K, D>) -> Result<LoadedCore<D>>;
}

impl<K, D: 'static, F> ModuleRelocator<K, D> for F
where
    F: for<'a> FnMut(RelocationRequest<'a, K, D>) -> Result<LoadedCore<D>>,
{
    #[inline]
    fn relocate(&mut self, req: RelocationRequest<'_, K, D>) -> Result<LoadedCore<D>> {
        (self)(req)
    }
}

struct LinkedStorage<K, D: 'static> {
    index: BTreeMap<K, usize>,
    entries: Vec<LinkedEntry<K, D>>,
}

impl<K, D: 'static> LinkedStorage<K, D> {
    #[inline]
    const fn new() -> Self {
        Self {
            index: BTreeMap::new(),
            entries: Vec::new(),
        }
    }
}

impl<K, D: 'static> LinkedStorage<K, D>
where
    K: Ord,
{
    #[inline]
    fn contains_key(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }

    #[inline]
    fn entry(&self, key: &K) -> Option<&LinkedEntry<K, D>> {
        self.index
            .get(key)
            .and_then(|&index| self.entries.get(index))
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    #[inline]
    fn get(&self, key: &K) -> Option<&LoadedCore<D>> {
        self.entry(key).map(|entry| &entry.module)
    }

    #[inline]
    fn push_new(&mut self, key: K, entry: LinkedEntry<K, D>) {
        let index = self.entries.len();
        let previous = self.index.insert(key, index);
        debug_assert!(
            previous.is_none(),
            "linked storage inserted a duplicate key"
        );
        self.entries.push(entry);
    }

    #[inline]
    fn view(&self) -> LinkedStorageView<'_, K, D> {
        LinkedStorageView {
            index: &self.index,
            entries: &self.entries,
        }
    }
}

struct LinkedStorageView<'a, K, D: 'static> {
    index: &'a BTreeMap<K, usize>,
    entries: &'a [LinkedEntry<K, D>],
}

impl<'a, K, D: 'static> Copy for LinkedStorageView<'a, K, D> {}

impl<'a, K, D: 'static> Clone for LinkedStorageView<'a, K, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static> LinkedStorageView<'a, K, D>
where
    K: Ord,
{
    #[inline]
    fn entry(&self, key: &K) -> Option<&'a LinkedEntry<K, D>> {
        self.index
            .get(key)
            .and_then(|&index| self.entries.get(index))
    }

    #[inline]
    fn iter(&self) -> impl Iterator<Item = &'a LoadedCore<D>> {
        self.entries.iter().map(|entry| &entry.module)
    }
}

/// Read-only view of the loaded modules currently visible to a load session.
///
/// The view can represent the stable contents of a [`LinkContext`] plus any
/// newly linked modules that were produced earlier in the current `load()`
/// call.
pub struct LinkContextView<'a, K, D: 'static> {
    committed: LinkedStorageView<'a, K, D>,
    staged: Option<LinkedStorageView<'a, K, D>>,
}

impl<'a, K, D: 'static> Copy for LinkContextView<'a, K, D> {}

impl<'a, K, D: 'static> Clone for LinkContextView<'a, K, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static> LinkContextView<'a, K, D>
where
    K: Ord,
{
    #[inline]
    fn new(
        committed: LinkedStorageView<'a, K, D>,
        staged: Option<LinkedStorageView<'a, K, D>>,
    ) -> Self {
        Self { committed, staged }
    }

    #[inline]
    fn visible_entry(&self, key: &K) -> Option<&'a LinkedEntry<K, D>> {
        self.staged
            .as_ref()
            .and_then(|staged| staged.entry(key))
            .or_else(|| self.committed.entry(key))
    }

    /// Returns whether the key is already present in the visible linked modules.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.visible_entry(key).is_some()
    }

    /// Returns the direct dependency keys recorded for a module.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        self.visible_entry(key)
            .map(|entry| entry.direct_deps.as_ref())
    }

    /// Iterates over the currently visible modules in load order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &'a LoadedCore<D>> {
        self.committed
            .iter()
            .chain(self.staged.iter().flat_map(|staged| staged.iter()))
    }

    /// Returns the visible module for a key.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&'a LoadedCore<D>> {
        self.visible_entry(key).map(|entry| &entry.module)
    }
}

/// A single dependency-resolution request.
pub struct DependencyRequest<'a, K, D: 'static> {
    owner_key: &'a K,
    owner: &'a RawDylib<D>,
    needed_index: usize,
    context: LinkContextView<'a, K, D>,
}

impl<'a, K, D: 'static> DependencyRequest<'a, K, D> {
    #[inline]
    fn new(
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
}

impl<'a, K, D: 'static> RelocationRequest<'a, K, D> {
    #[inline]
    fn new(key: &'a K, raw: RawDylib<D>, context: LinkContextView<'a, K, D>) -> Self {
        Self { key, raw, context }
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

    /// Consumes the request and returns all relocation inputs.
    #[inline]
    pub fn into_parts(self) -> (&'a K, RawDylib<D>, LinkContextView<'a, K, D>) {
        (self.key, self.raw, self.context)
    }
}

struct LinkedEntry<K, D: 'static> {
    module: LoadedCore<D>,
    direct_deps: Box<[K]>,
}

impl<K, D: 'static> Clone for LinkedEntry<K, D>
where
    K: Clone,
{
    fn clone(&self) -> Self {
        Self {
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
        }
    }
}

impl<K, D: 'static> LinkedEntry<K, D> {
    #[inline]
    fn new(module: LoadedCore<D>) -> Self {
        Self {
            module,
            direct_deps: Vec::new().into_boxed_slice(),
        }
    }

    #[inline]
    fn with_direct_deps(module: LoadedCore<D>, direct_deps: Box<[K]>) -> Self {
        Self {
            module,
            direct_deps,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingState {
    Unresolved,
    Visiting,
    Resolved,
}

struct PendingEntry<K, D: 'static> {
    raw: RawDylib<D>,
    direct_deps: Box<[K]>,
    state: PendingState,
}

impl<K, D: 'static> PendingEntry<K, D> {
    #[inline]
    fn new(raw: RawDylib<D>) -> Self {
        Self {
            raw,
            direct_deps: Vec::new().into_boxed_slice(),
            state: PendingState::Unresolved,
        }
    }
}

struct LoadSession<K, D: 'static> {
    pending: BTreeMap<K, PendingEntry<K, D>>,
    staged: LinkedStorage<K, D>,
    staged_keys: Vec<K>,
}

impl<K, D: 'static> LoadSession<K, D> {
    #[inline]
    fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            staged: LinkedStorage::new(),
            staged_keys: Vec::new(),
        }
    }
}

impl<K, D: 'static> LoadSession<K, D>
where
    K: Ord,
{
    #[inline]
    fn contains_pending(&self, key: &K) -> bool {
        self.pending.contains_key(key)
    }

    #[inline]
    fn contains_staged(&self, key: &K) -> bool {
        self.staged.contains_key(key)
    }

    #[inline]
    fn pending_entry(&self, key: &K) -> Result<&PendingEntry<K, D>> {
        self.pending
            .get(key)
            .ok_or_else(|| custom_error("missing module while resolving dependencies"))
    }

    #[inline]
    fn pending_entry_mut(&mut self, key: &K) -> Result<&mut PendingEntry<K, D>> {
        self.pending
            .get_mut(key)
            .ok_or_else(|| custom_error("missing module while resolving dependencies"))
    }

    #[inline]
    fn pending_state(&self, key: &K) -> Result<PendingState> {
        Ok(self.pending_entry(key)?.state)
    }

    #[inline]
    fn staged_entry(&self, key: &K) -> Option<&LinkedEntry<K, D>> {
        self.staged.entry(key)
    }
}

impl<K, D: 'static> LoadSession<K, D>
where
    K: Clone + Ord,
{
    #[inline]
    fn push_staged(&mut self, key: K, entry: LinkedEntry<K, D>) {
        self.staged_keys.push(key.clone());
        self.staged.push_new(key, entry);
    }
}

/// A reusable local module repository, dependency graph, and local relocation
/// coordinator.
///
/// This context stores only fully linked modules. Any raw objects that are
/// discovered while loading a new root live only inside that `load()` call and
/// are committed into the context once the whole load succeeds.
pub struct LinkContext<K, D: 'static> {
    committed: LinkedStorage<K, D>,
    scratch_relocation_order: Vec<K>,
}

impl<K, D: 'static> Default for LinkContext<K, D> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<K, D: 'static> LinkContext<K, D> {
    #[inline]
    pub const fn new() -> Self {
        Self {
            committed: LinkedStorage::new(),
            scratch_relocation_order: Vec::new(),
        }
    }
}

impl<K, D: 'static> LinkContext<K, D>
where
    K: Clone + Ord,
{
    /// Returns whether the context is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty()
    }

    /// Returns a read-only view over the current linked modules.
    #[inline]
    pub fn view(&self) -> LinkContextView<'_, K, D> {
        LinkContextView::new(self.committed.view(), None)
    }

    /// Loads one module into the context, recursively resolves its
    /// dependencies, relocates any newly discovered raw modules, and returns
    /// the cached loaded module.
    ///
    /// Repeated calls reuse already-loaded entries in the same context. The
    /// context itself is mutated only after the current load finishes
    /// successfully. The relocation callback receives a [`RelocationRequest`]
    /// describing each newly mapped module in dependency order.
    pub fn load<R, L>(
        &mut self,
        key: K,
        resolver: &mut R,
        relocator: &mut L,
    ) -> Result<LoadedCore<D>>
    where
        R: ModuleResolver<K, D>,
        L: ModuleRelocator<K, D>,
    {
        if let Some(loaded) = self.committed.get(&key) {
            return Ok(loaded.clone());
        }

        let mut session = LoadSession::new();
        let root = self.stage_resolved_module(resolver.load(&key)?, &mut session)?;

        if session.contains_pending(&root) {
            self.resolve_pending_dependencies(&root, &mut session, resolver)?;
            self.relocate_pending_modules(&root, &mut session, relocator)?;
        }

        let loaded = session
            .staged_entry(&root)
            .map(|entry| entry.module.clone())
            .or_else(|| self.committed.get(&root).cloned())
            .ok_or_else(|| custom_error("loaded module missing from link context after load"))?;

        self.commit_session(&mut session);
        Ok(loaded)
    }

    fn resolve_pending_dependencies<R>(
        &self,
        key: &K,
        session: &mut LoadSession<K, D>,
        resolver: &mut R,
    ) -> Result<()>
    where
        R: ModuleResolver<K, D>,
    {
        if self.is_visible_loaded(key, session) {
            return Ok(());
        }
        match session.pending_state(key)? {
            PendingState::Resolved | PendingState::Visiting => return Ok(()),
            PendingState::Unresolved => {}
        }
        session.pending_entry_mut(key)?.state = PendingState::Visiting;

        let result = (|| {
            let needed_len = session.pending_entry(key)?.raw.needed_libs().len();
            let mut direct_deps = Vec::with_capacity(needed_len);
            let mut seen_deps = BTreeSet::new();

            for idx in 0..needed_len {
                let dependency = self.resolve_dependency(key, idx, session, resolver)?;
                let dep_key = self.stage_resolved_module(dependency, session)?;
                if seen_deps.insert(dep_key.clone()) {
                    direct_deps.push(dep_key.clone());
                }
                if session.contains_pending(&dep_key) {
                    self.resolve_pending_dependencies(&dep_key, session, resolver)?;
                }
            }

            let entry = session.pending_entry_mut(key).map_err(|_| {
                custom_error("missing module while finalizing dependency resolution")
            })?;
            entry.direct_deps = direct_deps.into_boxed_slice();
            Ok(())
        })();

        session.pending_entry_mut(key)?.state = if result.is_ok() {
            PendingState::Resolved
        } else {
            PendingState::Unresolved
        };
        result
    }

    /// Relocates every pending raw module reachable from `root`.
    ///
    /// Modules are relocated in post-order so dependencies are finalized before
    /// dependents. The caller supplies the relocation policy via `relocate`,
    /// which receives a [`RelocationRequest`] describing the current key, raw
    /// module, and visible linked modules for this session.
    fn relocate_pending_modules<L>(
        &mut self,
        root: &K,
        session: &mut LoadSession<K, D>,
        relocator: &mut L,
    ) -> Result<()>
    where
        L: ModuleRelocator<K, D>,
    {
        let mut order = mem::take(&mut self.scratch_relocation_order);
        self.build_relocation_order(root, &session.pending, &mut order);

        let result = (|| {
            for key in order.drain(..) {
                let entry = session
                    .pending
                    .remove(&key)
                    .ok_or_else(|| custom_error("missing pending module while relocating"))?;
                let req = RelocationRequest::new(&key, entry.raw, self.session_view(session));
                let loaded = relocator.relocate(req)?;
                session.push_staged(
                    key,
                    LinkedEntry::with_direct_deps(loaded, entry.direct_deps),
                );
            }
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }

    fn build_relocation_order(
        &self,
        root: &K,
        pending: &BTreeMap<K, PendingEntry<K, D>>,
        order: &mut Vec<K>,
    ) {
        order.clear();
        if order.capacity() < pending.len() {
            order.reserve(pending.len() - order.capacity());
        }
        let mut visited = BTreeSet::new();
        self.collect_pending_postorder(root, pending, &mut visited, order);
    }

    fn collect_pending_postorder(
        &self,
        key: &K,
        pending: &BTreeMap<K, PendingEntry<K, D>>,
        visited: &mut BTreeSet<K>,
        order: &mut Vec<K>,
    ) {
        if !visited.insert(key.clone()) {
            return;
        }
        let Some(slot) = pending.get(key) else {
            return;
        };
        for dep in &slot.direct_deps {
            self.collect_pending_postorder(dep, pending, visited, order);
        }
        order.push(key.clone());
    }

    #[inline]
    fn session_view<'a>(&'a self, session: &'a LoadSession<K, D>) -> LinkContextView<'a, K, D> {
        LinkContextView::new(self.committed.view(), Some(session.staged.view()))
    }

    #[inline]
    fn is_visible_loaded(&self, key: &K, session: &LoadSession<K, D>) -> bool {
        session.contains_staged(key) || self.committed.contains_key(key)
    }

    #[inline]
    fn contains_known_key(&self, key: &K, session: &LoadSession<K, D>) -> bool {
        session.contains_pending(key) || self.is_visible_loaded(key, session)
    }

    fn resolve_dependency<R>(
        &self,
        owner_key: &K,
        needed_index: usize,
        session: &LoadSession<K, D>,
        resolver: &mut R,
    ) -> Result<ResolvedModule<K, D>>
    where
        R: ModuleResolver<K, D>,
    {
        let raw = &session.pending_entry(owner_key)?.raw;
        let req = DependencyRequest::new(owner_key, raw, needed_index, self.session_view(session));
        resolver.resolve(&req)?.ok_or_else(|| {
            custom_error(format!(
                "unresolved dependency [{}] needed by [{}]",
                req.needed(),
                req.owner().name()
            ))
        })
    }

    fn stage_resolved_module(
        &self,
        module: ResolvedModule<K, D>,
        session: &mut LoadSession<K, D>,
    ) -> Result<K> {
        match module {
            ResolvedModule::Existing(key) => {
                if self.is_visible_loaded(&key, session) {
                    Ok(key)
                } else {
                    Err(custom_error(
                        "resolved module referenced an unknown key without attaching a module",
                    ))
                }
            }
            ResolvedModule::Raw(key, raw) => {
                if self.contains_known_key(&key, session) {
                    Err(custom_error(
                        "resolved raw module attached an already-known key; use ResolvedModule::Existing to reuse a visible module",
                    ))
                } else {
                    session.pending.insert(key.clone(), PendingEntry::new(raw));
                    Ok(key)
                }
            }
            ResolvedModule::Loaded(key, loaded) => {
                if self.contains_known_key(&key, session) {
                    Err(custom_error(
                        "resolved loaded module attached an already-known key; use ResolvedModule::Existing to reuse a visible module",
                    ))
                } else {
                    session.push_staged(key.clone(), LinkedEntry::new(loaded));
                    Ok(key)
                }
            }
        }
    }

    fn commit_session(&mut self, session: &mut LoadSession<K, D>) {
        debug_assert_eq!(session.staged_keys.len(), session.staged.entries.len());

        for (key, entry) in session
            .staged_keys
            .drain(..)
            .zip(session.staged.entries.drain(..))
        {
            self.committed.push_new(key, entry);
        }
        session.staged.index.clear();
    }
}
