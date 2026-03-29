use super::{
    api::{ModuleRelocator, ModuleResolver, ResolvedModule},
    request::{DependencyRequest, RelocationRequest},
    session::{walk_breadth_first, LoadSession, PendingEntry, PendingState},
    storage::{CommittedEntry, CommittedStorage, StagedEntry, StagedStorage},
    view::LinkContextView,
};
use crate::{image::LoadedCore, LinkerError, Result, UnresolvedDependencyError};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::mem;

/// A reusable local module repository, dependency graph, and local relocation
/// coordinator.
///
/// This context stores only fully linked modules. Any raw objects that are
/// discovered while loading a new root live only inside that `load()` call and
/// are committed into the context once the whole load succeeds.
pub struct LinkContext<K, D: 'static> {
    committed: CommittedStorage<K, D>,
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
            committed: CommittedStorage::new(),
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
        let root = self.stage_resolved_module(resolver.load(&key)?, &mut session);

        if session.contains_pending(&root) {
            self.resolve_pending_dependencies(&root, &mut session, resolver)?;
            self.relocate_pending_modules(&root, &mut session, relocator)?;
        }

        self.commit_session(&mut session);

        let loaded = self
            .committed
            .get(&root)
            .expect("loaded module missing from link context after load")
            .clone();

        Ok(loaded)
    }

    fn resolve_pending_dependencies<R>(
        &self,
        root: &K,
        session: &mut LoadSession<K, D>,
        resolver: &mut R,
    ) -> Result<()>
    where
        R: ModuleResolver<K, D>,
    {
        if self.is_visible_loaded(root, session) {
            return Ok(());
        }
        match session.pending_state(root) {
            PendingState::Resolved | PendingState::Visiting => return Ok(()),
            PendingState::Unresolved => {}
        }

        session.pending_entry_mut(root).state = PendingState::Visiting;

        walk_breadth_first(root.clone(), |key, queue| {
            let needed_len = session.pending_entry(&key).raw.needed_libs().len();
            let mut direct_deps = Vec::with_capacity(needed_len);

            for idx in 0..needed_len {
                let dependency = self.resolve_dependency(&key, idx, session, resolver)?;
                let dep_key = self.stage_resolved_module(dependency, session);
                let should_queue = if let Some(entry) = session.pending.get_mut(&dep_key) {
                    if entry.state == PendingState::Unresolved {
                        entry.state = PendingState::Visiting;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                let is_new = !direct_deps.iter().any(|existing| existing == &dep_key);
                if should_queue && is_new {
                    queue.push(dep_key.clone());
                }
                if is_new {
                    direct_deps.push(dep_key);
                }
            }

            let entry = session.pending_entry_mut(&key);
            entry.direct_deps = direct_deps.into_boxed_slice();
            entry.state = PendingState::Resolved;
            Ok(())
        })
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
                    .expect("missing pending module while relocating");
                let req = RelocationRequest::new(&key, entry.raw, self.load_view(session));
                let loaded = relocator.relocate(req)?;
                session.insert_staged(StagedEntry::with_direct_deps(
                    key,
                    loaded,
                    entry.direct_deps,
                ));
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
        let mut visited: BTreeSet<&K> = BTreeSet::new();
        let mut stack = Vec::with_capacity(pending.len().saturating_mul(2));
        stack.push((root, false));

        while let Some((key, expanded)) = stack.pop() {
            if expanded {
                order.push(key.clone());
                continue;
            }

            if !visited.insert(key) {
                continue;
            }

            let Some(slot) = pending.get(key) else {
                continue;
            };

            stack.push((key, true));
            for dep in slot.direct_deps.iter().rev() {
                stack.push((dep, false));
            }
        }
    }

    #[inline]
    fn load_view<'a>(&'a self, session: &'a LoadSession<K, D>) -> LinkContextView<'a, K, D> {
        LinkContextView::new(self.committed.view(), Some(session.staged.view()))
    }

    #[inline]
    fn is_visible_loaded(&self, key: &K, session: &LoadSession<K, D>) -> bool {
        session.contains_staged(key) || self.committed.contains_key(key)
    }

    #[inline]
    fn is_known_key(&self, key: &K, session: &LoadSession<K, D>) -> bool {
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
        let raw = &session.pending_entry(owner_key).raw;
        let req = DependencyRequest::new(owner_key, raw, needed_index, self.load_view(session));
        resolver.resolve(&req)?.ok_or_else(|| {
            LinkerError::UnresolvedDependency(Box::new(UnresolvedDependencyError::new(
                req.owner().name(),
                req.needed(),
            )))
            .into()
        })
    }

    fn stage_resolved_module(
        &self,
        module: ResolvedModule<K, D>,
        session: &mut LoadSession<K, D>,
    ) -> K {
        match module {
            ResolvedModule::Existing(key) => {
                assert!(
                    self.is_visible_loaded(&key, session),
                    "resolved module referenced an unknown key without attaching a module"
                );
                key
            }
            ResolvedModule::Raw(key, raw) => {
                assert!(
                    !self.is_known_key(&key, session),
                    "resolved raw module attached an already-known key; use ResolvedModule::Existing to reuse a visible module"
                );
                session.insert_pending(key.clone(), raw);
                key
            }
            ResolvedModule::Loaded(key, loaded) => {
                assert!(
                    !self.is_known_key(&key, session),
                    "resolved loaded module attached an already-known key; use ResolvedModule::Existing to reuse a visible module"
                );
                session.insert_staged(StagedEntry::new(key.clone(), loaded));
                key
            }
        }
    }

    fn commit_session(&mut self, session: &mut LoadSession<K, D>) {
        let staged = mem::replace(&mut session.staged, StagedStorage::new());
        debug_assert_eq!(staged.index.len(), staged.entries.len());

        for entry in staged.entries {
            self.committed.push_new(
                entry.key,
                CommittedEntry::new(entry.module, entry.direct_deps),
            );
        }
    }
}
