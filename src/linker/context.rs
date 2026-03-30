use super::{
    api::{
        MaterializationRequest, ModuleMaterializer, ModuleRelocator, ModuleResolver, ResolvedModule,
    },
    plan::{LinkPipeline, LinkPlan},
    request::{DependencyRequest, RelocationRequest},
    scan::{ModuleScanner, ScanContext},
    session::{LoadSession, PendingEntry, PendingState, walk_breadth_first},
    storage::{CommittedEntry, CommittedStorage, StagedStorage},
    view::LinkContextView,
};
use crate::{LinkerError, Result, UnresolvedDependencyError, image::LoadedCore};
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
    scan: ScanContext<K, D>,
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
            scan: ScanContext::new(),
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
        self.load_impl(key, resolver, relocator)
    }

    /// Loads one module through the scan-first path:
    /// `scan -> plan -> materialize -> relocate -> commit`.
    ///
    /// This path keeps metadata discovery separate from the original
    /// map-first resolver flow and is the intended entry point for whole-graph
    /// planning such as cross-dylib layout or hugepage optimization.
    pub fn load_with_scan<S, M, L>(
        &mut self,
        key: K,
        scanner: &mut S,
        materializer: &mut M,
        relocator: &mut L,
    ) -> Result<LoadedCore<D>>
    where
        S: ModuleScanner<K, D>,
        M: ModuleMaterializer<K, D>,
        L: ModuleRelocator<K, D>,
    {
        self.load_with_scan_impl(key, scanner, None, materializer, relocator)
    }

    /// Loads one module through the scan-first path while running pre-map link
    /// passes over the discovered [`LinkPlan`] before materialization begins.
    pub fn load_with_scan_pipeline<'a, S, M, L>(
        &mut self,
        key: K,
        scanner: &mut S,
        pipeline: &mut LinkPipeline<'a, K, D>,
        materializer: &mut M,
        relocator: &mut L,
    ) -> Result<LoadedCore<D>>
    where
        S: ModuleScanner<K, D>,
        M: ModuleMaterializer<K, D>,
        L: ModuleRelocator<K, D>,
    {
        self.load_with_scan_impl(key, scanner, Some(pipeline), materializer, relocator)
    }

    fn load_impl<R, L>(
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

    fn load_with_scan_impl<'a, S, M, L>(
        &mut self,
        key: K,
        scanner: &mut S,
        mut pipeline: Option<&mut LinkPipeline<'a, K, D>>,
        materializer: &mut M,
        relocator: &mut L,
    ) -> Result<LoadedCore<D>>
    where
        S: ModuleScanner<K, D>,
        M: ModuleMaterializer<K, D>,
        L: ModuleRelocator<K, D>,
    {
        let mut plan = self.scan.discover(key, scanner)?;
        if let Some(pipeline) = pipeline.as_deref_mut() {
            pipeline.run(&mut plan)?;
        }

        if let Some(loaded) = self.committed.get(plan.root_key()) {
            return Ok(loaded.clone());
        }

        let root = plan.root_key().clone();
        let mut session = LoadSession::new();
        self.materialize_plan(&plan, &mut session, materializer)?;
        self.relocate_pending_modules(&root, &mut session, relocator)?;
        self.commit_session(&mut session);

        let loaded = self
            .committed
            .get(&root)
            .expect("loaded module missing from link context after scan load")
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
        let mut group_order = mem::take(&mut session.group_order);
        let mut visited = BTreeSet::new();
        let root = root.clone();
        visited.insert(root.clone());
        group_order.push(root);

        let result = walk_breadth_first(&mut group_order, |key, queue| {
            let needs_store = session.contains_pending(key)
                && matches!(session.pending_state(key), PendingState::Unresolved);
            let direct_deps = self.resolve_node_direct_deps(key, session, resolver)?;

            for dep_key in direct_deps.iter().cloned() {
                if visited.insert(dep_key.clone()) {
                    queue.push(dep_key);
                }
            }

            if needs_store {
                let entry = session.pending_entry_mut(key);
                entry.direct_deps = direct_deps.into_boxed_slice();
                entry.state = PendingState::Resolved;
            }

            Ok(())
        });

        session.group_order = group_order;
        result
    }

    fn resolve_node_direct_deps<R>(
        &self,
        key: &K,
        session: &mut LoadSession<K, D>,
        resolver: &mut R,
    ) -> Result<Vec<K>>
    where
        R: ModuleResolver<K, D>,
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
        let mut direct_deps = Vec::with_capacity(needed_len);

        for idx in 0..needed_len {
            let dependency = self.resolve_dependency(key, idx, session, resolver)?;
            let dep_key = self.stage_resolved_module(dependency, session);
            if !direct_deps.iter().any(|existing| existing == &dep_key) {
                direct_deps.push(dep_key);
            }
        }

        Ok(direct_deps)
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
                let req = RelocationRequest::new(
                    &key,
                    entry.raw,
                    self.load_view(session),
                    session.group_order.as_slice(),
                    session.scope_keys(&key),
                );
                let loaded = relocator.relocate(req)?;
                session.insert_staged(key, loaded, entry.direct_deps);
            }
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }

    fn materialize_plan<M>(
        &self,
        plan: &LinkPlan<K, D>,
        session: &mut LoadSession<K, D>,
        materializer: &mut M,
    ) -> Result<()>
    where
        M: ModuleMaterializer<K, D>,
    {
        session
            .group_order
            .extend(plan.group_order().iter().cloned());

        for key in plan.group_order() {
            let scope = plan.scope_keys(key);
            if scope != plan.group_order() {
                session.set_scope_override(key.clone(), scope.to_vec().into_boxed_slice());
            }

            if self.is_visible_loaded(key, session) {
                continue;
            }

            let module = plan
                .get(key)
                .expect("link plan referenced a missing scanned module");
            let direct_deps = plan.direct_deps(key).unwrap_or(&[]);
            let request = MaterializationRequest::new(
                key,
                module,
                direct_deps,
                plan,
                self.load_view(session),
            );
            let resolved = materializer.materialize(request)?;
            self.stage_materialized_module(key, direct_deps, resolved, session);
        }

        Ok(())
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
                    self.is_known_key(&key, session),
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
            ResolvedModule::Loaded(key, loaded, direct_deps) => {
                assert!(
                    !self.is_known_key(&key, session),
                    "resolved loaded module attached an already-known key; use ResolvedModule::Existing to reuse a visible module"
                );
                session.insert_staged(key.clone(), loaded, direct_deps);
                key
            }
        }
    }

    fn stage_materialized_module(
        &self,
        expected_key: &K,
        direct_deps: &[K],
        module: ResolvedModule<K, D>,
        session: &mut LoadSession<K, D>,
    ) {
        match module {
            ResolvedModule::Existing(key) => {
                assert!(
                    &key == expected_key,
                    "materializer changed the planned key; link plans must preserve canonical scan keys"
                );
                assert!(
                    self.is_visible_loaded(&key, session),
                    "materializer referenced an unknown visible key"
                );
            }
            ResolvedModule::Raw(key, raw) => {
                assert!(
                    &key == expected_key,
                    "materializer changed the planned key; link plans must preserve canonical scan keys"
                );
                assert!(
                    !self.is_known_key(&key, session),
                    "materializer attached a raw module to an already-known key"
                );
                session.insert_pending_resolved(key, raw, direct_deps.to_vec().into_boxed_slice());
            }
            ResolvedModule::Loaded(key, loaded, _) => {
                assert!(
                    &key == expected_key,
                    "materializer changed the planned key; link plans must preserve canonical scan keys"
                );
                assert!(
                    !self.is_known_key(&key, session),
                    "materializer attached a loaded module to an already-known key"
                );
                session.insert_staged(key, loaded, direct_deps.to_vec().into_boxed_slice());
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
