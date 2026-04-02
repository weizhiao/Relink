use super::{
    api::{KeyResolver, RelocationPlanner, ResolvedKey},
    layout::{LayoutPackingPolicy, MemoryLayoutPlan, PackSectionsPass},
    plan::{LinkPipeline, LinkPlan},
    request::{DependencyRequest, RelocationRequest},
    scan::ScanContext,
    session::{LoadSession, PendingEntry, PendingState, collect_unique_deps, extend_breadth_first},
    storage::{CommittedEntry, CommittedStorage, StagedStorage},
    view::LinkContextView,
};
use crate::{
    CustomError, LinkerError, Loader, Result, UnresolvedDependencyError,
    image::{LoadedCore, RawDylib},
    loader::LoadHook,
    os::Mmap,
    relocation::{RelocationHandler, Relocator, SymbolLookup},
    tls::TlsResolver,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::mem;

/// A reusable local module repository and committed dependency graph.
///
/// This context stores only fully linked modules. Any raw objects discovered
/// while loading a new root live only inside that specific load session and are
/// committed into the context once the whole load succeeds.
pub struct LinkContext<K, D: 'static> {
    committed: CommittedStorage<K, D>,
    scratch_relocation_order: Vec<K>,
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

    /// Returns whether a committed module exists for `key`.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.committed.contains_key(key)
    }

    /// Returns the committed module for `key`.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&LoadedCore<D>> {
        self.committed.get(key)
    }

    /// Returns the committed direct dependencies recorded for `key`.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<&[K]> {
        self.committed.view().direct_deps(key)
    }

    /// Returns the committed keys in load order.
    #[inline]
    pub fn load_order(&self) -> &[K] {
        self.committed.load_order()
    }

    /// Returns a read-only view over the current linked modules.
    #[inline]
    pub fn view(&self) -> LinkContextView<'_, K, D> {
        LinkContextView::new(self.committed.view(), None)
    }

    /// Inserts an already-loaded module into the committed context.
    ///
    /// This is intended for callers that bootstrap a process-global context
    /// from externally discovered shared objects.
    pub fn insert_loaded(
        &mut self,
        key: K,
        module: LoadedCore<D>,
        direct_deps: Box<[K]>,
    ) -> Result<()> {
        if self.committed.contains_key(&key) {
            return Err(CustomError::Message("duplicate linked module key".into()).into());
        }

        self.committed
            .insert_new(key, CommittedEntry::new(module, direct_deps));
        Ok(())
    }

    /// Removes a committed module from the context.
    #[inline]
    pub fn remove_loaded(&mut self, key: &K) -> bool {
        self.committed.remove(key).is_some()
    }

    /// Builds the transitive dependency scope for `root` in breadth-first order.
    pub fn dependency_scope_keys(&self, root: &K) -> Vec<K> {
        if !self.committed.contains_key(root) {
            return Vec::new();
        }

        let mut scope = Vec::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        visited.insert(root.clone());
        queue.push_back(root.clone());

        while let Some(key) = queue.pop_front() {
            let Some(entry) = self.committed.entry(&key) else {
                continue;
            };
            scope.push(key);

            for dep in entry.direct_deps.iter() {
                if visited.insert(dep.clone()) {
                    queue.push_back(dep.clone());
                }
            }
        }

        scope
    }

    /// Builds the transitive dependency scope for `root` in breadth-first order.
    pub fn dependency_scope(&self, root: &K) -> Arc<[LoadedCore<D>]> {
        let scope = self
            .dependency_scope_keys(root)
            .into_iter()
            .filter_map(|key| self.committed.get(&key).cloned())
            .collect::<Vec<_>>();
        Arc::from(scope)
    }

    /// Copies committed modules from another context into this one in source
    /// load order.
    pub fn extend_loaded(&mut self, other: &LinkContext<K, D>) -> Result<()> {
        for key in other.load_order() {
            if self.committed.contains_key(key) {
                continue;
            }

            let module = other
                .get(key)
                .cloned()
                .expect("load_order entries must resolve to committed modules");
            let direct_deps = other
                .direct_deps(key)
                .unwrap_or(&[])
                .to_vec()
                .into_boxed_slice();
            self.committed
                .insert_new(key.clone(), CommittedEntry::new(module, direct_deps));
        }
        Ok(())
    }

    /// Creates a committed-graph snapshot that can be used as an isolated load
    /// session and later merged back into the source context.
    pub fn snapshot(&self) -> Self {
        let mut snapshot = Self::new();
        snapshot
            .extend_loaded(self)
            .expect("link context snapshot must not fail");
        snapshot
    }

    /// Loads one module into the context, recursively resolves its
    /// dependencies, relocates any newly discovered raw modules, and returns
    /// the cached loaded module.
    ///
    /// Repeated calls reuse already-loaded entries in the same context. The
    /// context itself is mutated only after the current load finishes
    /// successfully. The relocation callback receives a [`RelocationRequest`]
    /// describing each newly mapped module in dependency order.
    pub fn load<'cfg, M, H, Tls, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        &mut self,
        key: K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'cfg, K, D>,
        relocator: &Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>,
        planner: &mut impl RelocationPlanner<K, D>,
    ) -> Result<LoadedCore<D>>
    where
        D: Default,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
        PreS: SymbolLookup + Clone,
        PostS: SymbolLookup + Clone,
        LazyPreS: SymbolLookup + Send + Sync + 'static + Clone,
        LazyPostS: SymbolLookup + Send + Sync + 'static + Clone,
        PreH: RelocationHandler + Clone,
        PostH: RelocationHandler + Clone,
    {
        if let Some(loaded) = self.committed.get(&key) {
            return Ok(loaded.clone());
        }

        let mut session = LoadSession::new();
        let root = self.stage_resolved_key(resolver.load_root(&key)?, &mut session, loader)?;

        if session.contains_pending(&root) {
            self.resolve_pending_dependencies(&root, &mut session, loader, resolver)?;
            self.relocate_pending_modules(&root, &mut session, None, relocator, planner)?;
        }

        self.commit_session(&mut session);

        let loaded = self
            .committed
            .get(&root)
            .expect("loaded module missing from link context after load")
            .clone();

        Ok(loaded)
    }

    /// Discovers and plans one module through the scan-first path.
    ///
    /// This returns a logical [`LinkPlan`] that keeps per-DSO identity intact
    /// even when later layout passes choose shared arenas or cross-DSO packing.
    /// The caller supplies strategy passes only; the core section-layout seed,
    /// retained-relocation capture, and derived-address rebuild are integrated
    /// internally.
    pub fn plan_with_scan<'a, M, H, Tls, Q: ?Sized>(
        &self,
        key: K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'static, K, D>,
        pipeline: &mut LinkPipeline<'a, K, D, Q>,
        queries: &mut Q,
    ) -> Result<LinkPlan<K, D>>
    where
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        let mut scan = ScanContext::new();
        let mut plan = scan.discover(key, self.view(), loader, resolver)?;
        plan.prepare_layout()?;
        pipeline.run(&mut plan, queries)?;
        plan.finalize_layout();
        Ok(plan)
    }

    /// Discovers one module and runs the default shared-hugepage packing pass.
    pub fn plan_with_layout<M, H, Tls>(
        &self,
        key: K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'static, K, D>,
    ) -> Result<LinkPlan<K, D>>
    where
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        self.plan_with_layout_policy(
            key,
            loader,
            resolver,
            LayoutPackingPolicy::shared_huge_pages(),
        )
    }

    /// Discovers one module and runs the default packing pass with an explicit
    /// arena policy.
    pub fn plan_with_layout_policy<M, H, Tls>(
        &self,
        key: K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'static, K, D>,
        policy: LayoutPackingPolicy,
    ) -> Result<LinkPlan<K, D>>
    where
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        let mut pack = PackSectionsPass::new(policy);
        let mut pipeline = LinkPipeline::new();
        pipeline.push(&mut pack);
        self.plan_with_scan(key, loader, resolver, &mut pipeline, &mut ())
    }

    fn resolve_pending_dependencies<'cfg, M, H, Tls>(
        &self,
        root: &K,
        session: &mut LoadSession<K, D>,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'cfg, K, D>,
    ) -> Result<()>
    where
        D: Default,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        let mut group_order = mem::take(&mut session.group_order);
        let result = extend_breadth_first(&mut group_order, root.clone(), |key| {
            let needs_store = session.contains_pending(key)
                && matches!(session.pending_state(key), PendingState::Unresolved);
            let direct_deps = self.resolve_node_direct_deps(key, session, loader, resolver)?;

            if needs_store {
                let entry = session.pending_entry_mut(key);
                entry.direct_deps = direct_deps.clone().into_boxed_slice();
                entry.state = PendingState::Resolved;
            }

            Ok(direct_deps)
        });

        session.group_order = group_order;
        result
    }

    fn resolve_node_direct_deps<'cfg, M, H, Tls>(
        &self,
        key: &K,
        session: &mut LoadSession<K, D>,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'cfg, K, D>,
    ) -> Result<Vec<K>>
    where
        D: Default,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        if !session.contains_pending(key) {
            return Ok(self
                .load_view(session)
                .direct_deps(key)
                .map_or_else(Vec::new, |deps| deps.to_vec()));
        }

        if matches!(session.pending_state(key), PendingState::Resolved) {
            return Ok(session.pending_entry(key).direct_deps.to_vec());
        }

        let needed_len = session.pending_entry(key).raw.needed_libs().len();
        collect_unique_deps(needed_len, |idx| {
            let dependency = self.resolve_dependency(key, idx, session, resolver)?;
            self.stage_resolved_key(dependency, session, loader)
        })
    }

    /// Relocates every pending raw module reachable from `root`.
    ///
    /// Modules are relocated in post-order so dependencies are finalized before
    /// dependents. The caller supplies the relocation policy via `relocate`,
    /// which receives a [`RelocationRequest`] describing the current key, raw
    /// module, and visible linked modules for this session.
    fn relocate_pending_modules<PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        &mut self,
        root: &K,
        session: &mut LoadSession<K, D>,
        memory_layout: Option<&MemoryLayoutPlan<K>>,
        relocator: &Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>,
        planner: &mut impl RelocationPlanner<K, D>,
    ) -> Result<()>
    where
        PreS: SymbolLookup + Clone,
        PostS: SymbolLookup + Clone,
        LazyPreS: SymbolLookup + Send + Sync + 'static + Clone,
        LazyPostS: SymbolLookup + Send + Sync + 'static + Clone,
        PreH: RelocationHandler + Clone,
        PostH: RelocationHandler + Clone,
    {
        let mut order = mem::take(&mut self.scratch_relocation_order);
        self.build_relocation_order(root, &session.pending, &mut order);

        let result = (|| {
            for key in order.drain(..) {
                let entry = session
                    .pending
                    .remove(&key)
                    .expect("missing pending module while relocating");
                let scope = self.build_scope_snapshot(&key, &entry.raw, session);
                let req = RelocationRequest::new(
                    &key,
                    entry.raw,
                    self.load_view(session),
                    session.scope_keys(&key),
                    scope,
                    memory_layout,
                );
                let inputs = planner.plan(&req)?;
                let raw = req.into_raw();
                let mut active = relocator.clone();
                active.replace_scope(inputs.scope().iter());
                active.set_binding(inputs.binding());
                let loaded = active.replace_object(raw).relocate()?;
                session.insert_staged(key, (*loaded).clone(), entry.direct_deps);
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

    fn build_scope_snapshot(
        &self,
        key: &K,
        raw: &RawDylib<D>,
        session: &LoadSession<K, D>,
    ) -> Box<[LoadedCore<D>]>
    where
        K: Clone + Ord,
    {
        let staged = session.staged.view();
        session
            .scope_keys(key)
            .iter()
            .map(|scope_key| {
                if scope_key == key {
                    unsafe { LoadedCore::from_core(raw.core()) }
                } else if let Some(module) = staged.get(scope_key) {
                    module.clone()
                } else if let Some(entry) = session.pending.get(scope_key) {
                    unsafe { LoadedCore::from_core(entry.raw.core()) }
                } else {
                    self.committed
                        .get(scope_key)
                        .cloned()
                        .expect("scope key must resolve to a visible or pending module")
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
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

    fn resolve_dependency<'cfg>(
        &self,
        owner_key: &K,
        needed_index: usize,
        session: &LoadSession<K, D>,
        resolver: &mut impl KeyResolver<'cfg, K, D>,
    ) -> Result<ResolvedKey<'cfg, K>> {
        let raw = &session.pending_entry(owner_key).raw;
        let req = DependencyRequest::new(owner_key, raw, needed_index, self.load_view(session));
        resolver.resolve_dependency(&req)?.ok_or_else(|| {
            LinkerError::UnresolvedDependency(Box::new(UnresolvedDependencyError::new(
                req.owner_name(),
                req.needed(),
            )))
            .into()
        })
    }

    fn stage_resolved_key<'cfg, M, H, Tls>(
        &self,
        resolved: ResolvedKey<'cfg, K>,
        session: &mut LoadSession<K, D>,
        loader: &mut Loader<M, H, D, Tls>,
    ) -> Result<K>
    where
        D: Default,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        match resolved {
            ResolvedKey::Existing(key) => {
                if !self.is_known_key(&key, session) {
                    return Err(CustomError::Message(
                        "resolved existing module is not visible in the current link context"
                            .into(),
                    )
                    .into());
                }
                Ok(key)
            }
            ResolvedKey::Load(key, reader) => {
                let raw = loader.load_dylib_impl(reader)?;
                assert!(
                    !self.is_known_key(&key, session),
                    "resolved reader produced an already-known key; use ResolvedKey::Existing to reuse a visible module"
                );
                session.insert_pending(key.clone(), raw);
                Ok(key)
            }
        }
    }

    fn commit_session(&mut self, session: &mut LoadSession<K, D>) {
        let staged = mem::replace(&mut session.staged, StagedStorage::new());
        for entry in staged.entries.into_values() {
            self.committed.insert_new(
                entry.key,
                CommittedEntry::new(entry.module, entry.direct_deps),
            );
        }
    }
}
