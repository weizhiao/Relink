use super::{
    api::{KeyResolver, RelocationPlanner},
    layout::{
        LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutClassPolicy, LayoutMemoryClass,
        LayoutModuleMaterialization, LayoutPackingPolicy, LayoutSectionData, LayoutSectionId,
        LayoutSectionKind, MemoryLayoutPlan, ModuleLayout, SectionPlacement,
    },
    plan::{LinkModuleId, LinkPipeline, LinkPlan},
    request::RelocationRequest,
    resolve::{LoadResolveContext, ScanResolveContext},
    runtime,
    session::{GraphEntry, LoadSession, ResolveSession},
    storage::{CommittedEntry, CommittedStorage},
    view::DependencyGraphView,
};
use crate::{
    CustomError, Loader, Result,
    image::{LoadedCore, ModuleCapability, RawDylib},
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
/// This context stores only committed modules. Any raw objects discovered
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

    /// Returns a read-only view over the current committed dependency graph.
    #[inline]
    pub fn view(&self) -> DependencyGraphView<'_, K, D> {
        DependencyGraphView::new_committed(self.committed.view())
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
        K: 'cfg,
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

        let prepared = self.prepare_runtime_load(key, loader, resolver)?;
        self.execute_prepared_load::<M, _, _, _, _, _, _>(prepared, relocator, planner)
    }

    /// Discovers, plans, and loads one module through the scan-first path.
    ///
    /// Caller-driven layout and materialization changes should be expressed as
    /// [`LinkPass`]es in `pipeline`, which run after scan discovery and before
    /// runtime materialization.
    pub fn load_with_scan<'a, M, H, Tls, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        &mut self,
        key: K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'static, K, D>,
        pipeline: &mut LinkPipeline<'a, K, D>,
        relocator: &Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>,
        planner: &mut impl RelocationPlanner<K, D>,
    ) -> Result<LoadedCore<D>>
    where
        D: Default,
        K: 'static,
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

        let plan = self.discover_scan_plan(key, loader, resolver, pipeline)?;
        let prepared = self.prepare_planned_load::<M, _, _>(plan, loader)?;
        self.execute_prepared_load::<M, _, _, _, _, _, _>(prepared, relocator, planner)
    }

    fn prepare_runtime_load<'cfg, M, H, Tls>(
        &self,
        key: K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'cfg, K, D>,
    ) -> Result<PreparedLoad<K, D>>
    where
        D: Default,
        K: 'cfg,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        let mut session = LoadSession::new();
        let mut context = LoadResolveContext::new(self.committed.view(), &mut session.resolve);
        let root = context.stage_resolved(resolver.load_root(&key)?, loader)?;
        if context.contains_pending(&root) {
            context.resolve_dependency_graph(root.clone(), loader, resolver)?;
        }

        Ok(PreparedLoad::runtime(root, session))
    }

    fn discover_scan_plan<'a, M, H, Tls>(
        &self,
        key: K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'static, K, D>,
        pipeline: &mut LinkPipeline<'a, K, D>,
    ) -> Result<LinkPlan<K, D>>
    where
        K: 'static,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        let mut session = ResolveSession::new();
        let mut context = ScanResolveContext::new(self.committed.view(), &mut session);
        let root = context.stage_resolved(resolver.load_root(&key)?, loader)?;
        {
            context.resolve_dependency_graph(root.clone(), loader, resolver)?;
        }

        let ResolveSession {
            entries,
            group_order,
        } = session;
        let mut plan = LinkPlan::new(
            root,
            group_order,
            entries
                .into_iter()
                .map(|(key, entry)| {
                    let direct_deps = entry
                        .direct_deps
                        .expect("missing resolved dependencies while building scan plan");
                    (key, (entry.payload, direct_deps))
                })
                .collect(),
        );
        pipeline.run(&mut plan)?;
        Ok(plan)
    }

    fn prepare_planned_load<M, H, Tls>(
        &self,
        mut plan: LinkPlan<K, D>,
        loader: &mut Loader<M, H, D, Tls>,
    ) -> Result<PreparedLoad<K, D>>
    where
        D: Default,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        // Scan discovery already seeded layout-side metadata before the pass pipeline ran.
        // The planned-load phase only needs to normalize materialization choices and rebuild
        // any derived addresses that those choices affect.
        normalize_materialization_plan(&mut plan)?;
        plan.finalize_layout()?;
        let mut mapped_section_arenas = map_planned_section_arenas::<M, _, _>(&mut plan)?;

        if let Some(mapped_section_arenas) = mapped_section_arenas.as_mut() {
            let section_region_modules = plan
                .group_order_ids()
                .iter()
                .copied()
                .filter(|module_id| {
                    plan.module_materialization(*module_id)
                        .unwrap_or(LayoutModuleMaterialization::WholeDsoRegion)
                        == LayoutModuleMaterialization::SectionRegions
                })
                .collect::<Vec<_>>();
            for module_id in section_region_modules {
                runtime::repair_arena_layout_module(module_id, &mut plan, mapped_section_arenas)?;
            }
            runtime::populate_mapped_arenas(plan.memory_layout(), mapped_section_arenas)?;
        }

        let (root, group_order, entries, memory_layout) = plan.into_parts();
        let (init_fn, fini_fn) = loader.inner.lifecycle_handlers();
        let force_static_tls = loader.inner.force_static_tls();
        let mut session = LoadSession::new();
        let module_keys = entries
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut entries = entries.into_iter().map(Some).collect::<Vec<_>>();
        session.resolve.group_order = group_order
            .iter()
            .map(|module_id| module_keys[module_id.index()].clone())
            .collect();

        let mut materialize_raw = |module_id: LinkModuleId,
                                   scanned: crate::image::ScannedDylib<D>|
         -> Result<RawDylib<D>> {
            match memory_layout
                .module_materialization(module_id)
                .unwrap_or(LayoutModuleMaterialization::WholeDsoRegion)
            {
                LayoutModuleMaterialization::SectionRegions => {
                    let mut raw = runtime::build_arena_raw_dylib::<D, Tls>(
                        module_id,
                        scanned,
                        &memory_layout,
                        mapped_section_arenas.as_ref().ok_or_else(|| {
                            crate::custom_error(
                                "section-region planned load is missing its mapped arenas",
                            )
                        })?,
                        init_fn.clone(),
                        fini_fn.clone(),
                        force_static_tls,
                    )?;
                    loader.inner.post_load_dylib(&mut raw)?;
                    Ok(raw)
                }
                LayoutModuleMaterialization::WholeDsoRegion => {
                    let mut raw = loader.load_dylib_impl(scanned.into_reader())?;
                    apply_planned_section_overrides(&mut raw, module_id, &memory_layout)?;
                    Ok(raw)
                }
            }
        };

        for module_id in &group_order {
            let entry = entries[module_id.index()]
                .take()
                .expect("planned load group order referenced a missing module entry");
            let (key, module, direct_dep_ids) = entry.into_parts();
            let direct_deps = direct_dep_ids
                .iter()
                .map(|dep_id| module_keys[dep_id.index()].clone())
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let raw = materialize_raw(*module_id, module)?;
            session.insert_resolved_pending(key, raw, direct_deps);
        }

        Ok(PreparedLoad::planned(
            module_keys[root.index()].clone(),
            session,
            mapped_section_arenas,
        ))
    }

    fn execute_prepared_load<M, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        &mut self,
        prepared: PreparedLoad<K, D>,
        relocator: &Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>,
        planner: &mut impl RelocationPlanner<K, D>,
    ) -> Result<LoadedCore<D>>
    where
        D: Default,
        M: Mmap,
        PreS: SymbolLookup + Clone,
        PostS: SymbolLookup + Clone,
        LazyPreS: SymbolLookup + Send + Sync + 'static + Clone,
        LazyPostS: SymbolLookup + Send + Sync + 'static + Clone,
        PreH: RelocationHandler + Clone,
        PostH: RelocationHandler + Clone,
    {
        let PreparedLoad {
            root,
            mut session,
            mapped_section_arenas,
        } = prepared;

        if !session.resolve.entries.is_empty() {
            self.relocate_pending_modules(&root, &mut session, relocator, planner)?;
        }

        if let Some(mapped_section_arenas) = mapped_section_arenas.as_ref() {
            runtime::protect_mapped_arenas::<M>(mapped_section_arenas)?;
        }

        self.commit_session(&mut session);

        self.committed
            .get(&root)
            .cloned()
            .ok_or_else(|| crate::custom_error("load root missing after commit"))
    }

    /// Relocates every pending raw module reachable from `root`.
    ///
    /// Modules are relocated in post-order so dependencies are finalized before
    /// dependents. The caller supplies the relocation policy via `planner`,
    /// which receives a [`RelocationRequest`] describing the current key, raw
    /// module, and the batch-start relocation scope snapshot for this session.
    fn relocate_pending_modules<PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        &mut self,
        root: &K,
        session: &mut LoadSession<K, D>,
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
        self.build_relocation_order(root, &session.resolve.entries, &mut order);
        let scope = self.build_group_scope(session);

        let result = (|| {
            for key in order.drain(..) {
                let entry = session
                    .resolve
                    .entries
                    .remove(&key)
                    .expect("missing pending module while relocating");
                let direct_deps = entry
                    .direct_deps
                    .expect("missing resolved dependencies while relocating");
                let req = RelocationRequest::new(&key, entry.payload, &scope);
                let inputs = planner.plan(&req)?;
                let raw = req.into_raw();
                let mut active = relocator.clone();
                active.replace_scope(inputs.scope().iter());
                active.set_binding(inputs.binding());
                let loaded = active.replace_object(raw).relocate()?;
                session.push_ready(key, (*loaded).clone(), direct_deps);
            }
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }

    fn build_relocation_order(
        &self,
        root: &K,
        pending: &BTreeMap<K, GraphEntry<K, RawDylib<D>>>,
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
            let direct_deps = slot
                .direct_deps
                .as_deref()
                .expect("missing resolved dependencies while building relocation order");
            for dep in direct_deps.iter().rev() {
                stack.push((dep, false));
            }
        }
    }

    fn build_group_scope(&self, session: &LoadSession<K, D>) -> Vec<LoadedCore<D>>
    where
        K: Ord,
    {
        // This snapshot is intentionally built once for the whole pending group.
        // Pending modules contribute placeholder LoadedCore values until the
        // session is committed into the stable context.
        session
            .resolve
            .group_order
            .iter()
            .map(|scope_key| {
                if let Some(entry) = session.resolve.entries.get(scope_key) {
                    unsafe { LoadedCore::from_core(entry.payload.core()) }
                } else {
                    self.committed
                        .get(scope_key)
                        .cloned()
                        .expect("scope key must resolve to a visible or pending module")
                }
            })
            .collect()
    }

    fn commit_session(&mut self, session: &mut LoadSession<K, D>) {
        let ready = mem::take(&mut session.ready_to_commit);
        for entry in ready {
            self.committed.insert_new(
                entry.key,
                CommittedEntry::new(entry.module, entry.direct_deps),
            );
        }
    }
}

struct PreparedLoad<K, D: 'static> {
    root: K,
    session: LoadSession<K, D>,
    mapped_section_arenas: Option<runtime::MappedArenaMap>,
}

impl<K, D: 'static> PreparedLoad<K, D> {
    fn runtime(root: K, session: LoadSession<K, D>) -> Self {
        Self {
            root,
            session,
            mapped_section_arenas: None,
        }
    }

    fn planned(
        root: K,
        session: LoadSession<K, D>,
        mapped_section_arenas: Option<runtime::MappedArenaMap>,
    ) -> Self {
        Self {
            root,
            session,
            mapped_section_arenas,
        }
    }
}

fn map_planned_section_arenas<M, K, D>(
    plan: &mut LinkPlan<K, D>,
) -> Result<Option<runtime::MappedArenaMap>>
where
    K: Clone + Ord,
    D: 'static,
    M: Mmap,
{
    let needs_section_regions = plan.group_order_ids().iter().copied().any(|module_id| {
        plan.module_materialization(module_id) == Some(LayoutModuleMaterialization::SectionRegions)
    });
    if !needs_section_regions {
        return Ok(None);
    }

    if !plan.memory_layout().has_section_placements() {
        return Ok(None);
    }

    let sections_to_materialize = plan
        .memory_layout()
        .sections()
        .iter_records()
        .filter_map(|(section_id, record)| {
            (record.placement().is_some()
                && record.metadata().is_allocated()
                && record.data().is_none())
            .then_some(section_id)
        })
        .collect::<Vec<_>>();
    for section_id in sections_to_materialize {
        let _ = plan.section_data(section_id)?;
    }

    runtime::map_layout_arenas::<M>(plan.memory_layout()).map(Some)
}

fn apply_planned_section_overrides<D>(
    raw: &mut RawDylib<D>,
    module_id: LinkModuleId,
    layout: &MemoryLayoutPlan,
) -> Result<()> {
    let module = layout
        .module(module_id)
        .expect("planned layout missing module for committed module id");
    let segments = raw.core_ref().segments();

    for section_id in module.alloc_sections().iter().copied() {
        if !layout.section_overrides_original_data(section_id) {
            continue;
        }
        let metadata = layout.section_metadata(section_id);
        let Some(data) = layout.sections().data(section_id) else {
            continue;
        };
        let dst = segments.get_slice_mut::<u8>(metadata.original_address(), metadata.size());
        write_planned_section_override(dst, data)?;
    }

    Ok(())
}

fn write_planned_section_override(dst: &mut [u8], data: &LayoutSectionData) -> Result<()> {
    match data {
        LayoutSectionData::Bytes(bytes) => {
            assert_eq!(
                bytes.len(),
                dst.len(),
                "planned section override size does not match the loaded section"
            );
            dst.copy_from_slice(bytes.as_ref());
        }
        LayoutSectionData::ZeroFill { .. } => dst.fill(0),
    }

    Ok(())
}

fn normalize_materialization_plan<K, D>(plan: &mut LinkPlan<K, D>) -> Result<()>
where
    K: Clone + Ord,
    D: 'static,
{
    let mut has_section_regions = false;

    plan.try_for_each_module(|plan, module_id| {
        let mode = {
            let layout = plan.memory_layout();
            let module = layout
                .module(module_id)
                .expect("ordered layout referenced a missing module layout");
            resolve_materialization_mode(&*plan, module_id, module)?
        };
        has_section_regions |= mode == LayoutModuleMaterialization::SectionRegions;
        let _ = plan.set_module_materialization(module_id, mode);
        Ok(())
    })?;

    if !has_section_regions {
        return Ok(());
    }

    let policy = LayoutPackingPolicy::shared_huge_pages();
    let mut arena_state = FallbackArenaState::new();

    plan.try_for_each_module(|plan, module_id| {
        let layout = plan.memory_layout();
        if layout.module_materialization(module_id)
            != Some(LayoutModuleMaterialization::SectionRegions)
        {
            return Ok(());
        }

        let section_count = layout
            .module(module_id)
            .expect("planned layout missing module for touched id")
            .alloc_sections()
            .len();
        for section_index in 0..section_count {
            let section_id = layout
                .module(module_id)
                .expect("planned layout missing module for touched id")
                .alloc_sections()[section_index];
            if let Some(placement) = layout.section_placement(section_id) {
                arena_state.absorb_existing_section(layout, module_id, section_id, placement);
            }
        }
        Ok(())
    })?;

    plan.try_for_each_module(|plan, module_id| {
        let section_count = {
            let layout = plan.memory_layout();
            if layout.module_materialization(module_id)
                != Some(LayoutModuleMaterialization::SectionRegions)
            {
                return Ok(());
            }
            layout
                .module(module_id)
                .expect("planned layout missing module for touched id")
                .alloc_sections()
                .len()
        };
        for section_index in 0..section_count {
            let section_id = {
                let layout = plan.memory_layout();
                layout
                    .module(module_id)
                    .expect("planned layout missing module for touched id")
                    .alloc_sections()[section_index]
            };
            if plan.memory_layout().section_placement(section_id).is_some() {
                continue;
            }
            assign_fallback_section(
                plan.memory_layout_mut(),
                module_id,
                section_id,
                policy,
                &mut arena_state,
            )?;
        }
        Ok(())
    })?;

    Ok(())
}

fn resolve_materialization_mode<K, D>(
    plan: &LinkPlan<K, D>,
    module_id: LinkModuleId,
    module: &ModuleLayout,
) -> Result<LayoutModuleMaterialization>
where
    K: Clone + Ord,
    D: 'static,
{
    let layout = plan.memory_layout();
    let capability = plan
        .module_capability(module_id)
        .expect("ordered layout referenced a module without capability metadata");
    let requested = layout
        .module_materialization(module_id)
        .expect("ordered layout referenced a module without materialization mode");
    let has_section_placement = module
        .alloc_sections()
        .iter()
        .any(|section_id| layout.section_placement(*section_id).is_some());

    match capability {
        ModuleCapability::Opaque | ModuleCapability::SectionData => {
            if has_section_placement {
                return Err(crate::custom_error(
                    "modules without section-reorder repair support cannot assign sections to arenas",
                ));
            }
            match requested {
                LayoutModuleMaterialization::WholeDsoRegion => {
                    Ok(LayoutModuleMaterialization::WholeDsoRegion)
                }
                LayoutModuleMaterialization::SectionRegions => Err(crate::custom_error(
                    "modules without section-reorder repair support cannot use section regions",
                )),
            }
        }
        ModuleCapability::SectionReorderable => {
            if has_section_placement || requested == LayoutModuleMaterialization::SectionRegions {
                Ok(LayoutModuleMaterialization::SectionRegions)
            } else {
                Ok(LayoutModuleMaterialization::WholeDsoRegion)
            }
        }
    }
}

fn assign_fallback_section(
    layout: &mut MemoryLayoutPlan,
    module_id: LinkModuleId,
    section_id: LayoutSectionId,
    policy: LayoutPackingPolicy,
    arena_state: &mut FallbackArenaState,
) -> Result<()> {
    let (memory_class, alignment, size) = {
        let section = layout.section_metadata(section_id);
        (
            match section.kind() {
                LayoutSectionKind::Allocated(class) => class,
                _ => panic!("fallback arena assignment encountered a non-alloc section"),
            },
            section.alignment(),
            section.size(),
        )
    };
    let arena_id = arena_state.ensure_arena(
        layout,
        module_id,
        policy.class_policy(memory_class),
        memory_class,
    );
    let offset = arena_state.next_offset(arena_id, alignment)?;
    let next_offset = offset
        .checked_add(size)
        .expect("fallback arena assignment overflowed while placing a section");

    assert!(
        layout.assign_section_to_arena(section_id, arena_id, offset),
        "fallback arena assignment failed while placing a section"
    );

    arena_state.update_arena_end(arena_id, next_offset);
    Ok(())
}

struct FallbackArenaState {
    shared_arenas: BTreeMap<(LayoutMemoryClass, usize), LayoutArenaId>,
    private_arenas: BTreeMap<(LinkModuleId, LayoutMemoryClass), LayoutArenaId>,
    arena_offsets: BTreeMap<LayoutArenaId, usize>,
}

impl FallbackArenaState {
    fn new() -> Self {
        Self {
            shared_arenas: BTreeMap::new(),
            private_arenas: BTreeMap::new(),
            arena_offsets: BTreeMap::new(),
        }
    }

    fn absorb_existing_section(
        &mut self,
        layout: &MemoryLayoutPlan,
        module_id: LinkModuleId,
        section_id: LayoutSectionId,
        placement: SectionPlacement,
    ) {
        let metadata = layout.section_metadata(section_id);
        let memory_class = match metadata.kind() {
            LayoutSectionKind::Allocated(class) => class,
            _ => panic!("fallback arena state found a non-alloc placed section"),
        };
        let arena = layout.arena(placement.arena());

        self.update_arena_end(
            placement.arena(),
            placement.offset().saturating_add(placement.size()),
        );
        self.remember_arena(module_id, memory_class, placement.arena(), arena);
    }

    fn remember_arena(
        &mut self,
        module_id: LinkModuleId,
        memory_class: LayoutMemoryClass,
        arena_id: LayoutArenaId,
        arena: &LayoutArena,
    ) {
        match arena.sharing() {
            LayoutArenaSharing::Shared => {
                self.shared_arenas
                    .entry((memory_class, arena.page_size()))
                    .or_insert(arena_id);
            }
            LayoutArenaSharing::Private => {
                self.private_arenas
                    .entry((module_id, memory_class))
                    .or_insert(arena_id);
            }
        }
    }

    fn ensure_arena(
        &mut self,
        layout: &mut MemoryLayoutPlan,
        module_id: LinkModuleId,
        class_policy: LayoutClassPolicy,
        memory_class: LayoutMemoryClass,
    ) -> LayoutArenaId {
        match class_policy.sharing() {
            LayoutArenaSharing::Shared => {
                let arena_key = (memory_class, class_policy.page_size());
                if let Some(arena_id) = self.shared_arenas.get(&arena_key).copied() {
                    return arena_id;
                }

                if let Some(arena_id) = Self::find_shared_arena(layout, class_policy, memory_class)
                {
                    self.remember_existing_arena_end(layout, arena_id);
                    self.shared_arenas.insert(arena_key, arena_id);
                    return arena_id;
                }

                let arena_id = layout.create_arena(LayoutArena::new(
                    class_policy.page_size(),
                    memory_class,
                    LayoutArenaSharing::Shared,
                ));
                self.shared_arenas.insert(arena_key, arena_id);
                arena_id
            }
            LayoutArenaSharing::Private => *self
                .private_arenas
                .entry((module_id, memory_class))
                .or_insert_with(|| {
                    layout.create_arena(LayoutArena::new(
                        class_policy.page_size(),
                        memory_class,
                        LayoutArenaSharing::Private,
                    ))
                }),
        }
    }

    fn find_shared_arena(
        layout: &MemoryLayoutPlan,
        class_policy: LayoutClassPolicy,
        memory_class: LayoutMemoryClass,
    ) -> Option<LayoutArenaId> {
        layout.arena_entries().find_map(|(arena_id, arena)| {
            (arena.sharing() == LayoutArenaSharing::Shared
                && arena.memory_class() == memory_class
                && arena.page_size() == class_policy.page_size())
            .then_some(arena_id)
        })
    }

    fn remember_existing_arena_end(&mut self, layout: &MemoryLayoutPlan, arena_id: LayoutArenaId) {
        if let Some(usage) = layout.arena_usage(arena_id) {
            self.update_arena_end(arena_id, usage.used_len());
        }
    }

    fn next_offset(&self, arena_id: LayoutArenaId, alignment: usize) -> Result<usize> {
        align_up(
            self.arena_offsets.get(&arena_id).copied().unwrap_or(0),
            alignment,
        )
    }

    fn update_arena_end(&mut self, arena_id: LayoutArenaId, end: usize) {
        self.arena_offsets
            .entry(arena_id)
            .and_modify(|offset| *offset = (*offset).max(end))
            .or_insert(end);
    }
}

fn align_up(value: usize, alignment: usize) -> Result<usize> {
    let alignment = alignment.max(1);
    let remainder = value % alignment;
    if remainder == 0 {
        return Ok(value);
    }

    value
        .checked_add(alignment - remainder)
        .ok_or_else(|| crate::custom_error("arena assignment overflowed while aligning offsets"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_shared_arena_reuses_existing_compatible_arena() {
        let mut layout = MemoryLayoutPlan::new();
        let arena_id = layout.create_arena(LayoutArena::new(
            2 * 1024 * 1024,
            LayoutMemoryClass::Code,
            LayoutArenaSharing::Shared,
        ));
        let mut state = FallbackArenaState::new();

        let selected = state.ensure_arena(
            &mut layout,
            LinkModuleId::new(0),
            LayoutClassPolicy::new(2 * 1024 * 1024, LayoutArenaSharing::Shared),
            LayoutMemoryClass::Code,
        );

        assert_eq!(selected, arena_id);
        assert_eq!(layout.arenas().len(), 1);
    }

    #[test]
    fn fallback_shared_arena_keeps_policy_page_size() {
        let mut layout = MemoryLayoutPlan::new();
        let small_page_arena = layout.create_arena(LayoutArena::new(
            4 * 1024,
            LayoutMemoryClass::Code,
            LayoutArenaSharing::Shared,
        ));
        let mut state = FallbackArenaState::new();

        let selected = state.ensure_arena(
            &mut layout,
            LinkModuleId::new(0),
            LayoutClassPolicy::new(2 * 1024 * 1024, LayoutArenaSharing::Shared),
            LayoutMemoryClass::Code,
        );

        assert_ne!(selected, small_page_arena);
        assert_eq!(layout.arenas().len(), 2);
    }
}
