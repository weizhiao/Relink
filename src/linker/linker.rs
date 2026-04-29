use super::{
    context::LinkContext,
    layout::{Materialization, MemoryLayoutPlan},
    mapped, materialization,
    plan::{LinkPipeline, LinkPlan, ModuleId},
    request::{
        DefaultRelocationPlanner, LoadObserver, RelocationPlanner, RelocationRequest, StagedDylib,
        VisibleModules,
    },
    resolve::{KeyResolver, LoadResolveContext, ScanResolveContext},
    session::{GraphEntry, LoadSession, ResolveSession},
    storage::CommittedEntry,
};
use crate::{
    LinkerError, Loader, Result,
    entity::SecondaryMap,
    image::{LoadedCore, RawDylib, ScannedDylib},
    loader::LoadHook,
    os::{DefaultMmap, Mmap},
    relocation::{RelocationHandler, Relocator, SymbolLookup},
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::mem;

/// Configurable front-end for dependency discovery, planning, and relocation.
///
/// A `Linker` owns the per-load policy: pre-map planning passes, relocation
/// hooks, relocation-scope planning, dependency resolution, and the concrete
/// loader. The [`LinkContext`] passed to [`Linker::load`] or
/// [`Linker::load_scan_first`] remains the committed module repository.
pub struct Linker<
    'a,
    K: Clone + Ord,
    D: 'static,
    L = Loader<DefaultMmap, (), D, ()>,
    R = (),
    PreS = (),
    PostS = (),
    LazyPreS = (),
    LazyPostS = (),
    PreH = (),
    PostH = (),
    ScopeD = (),
    P = DefaultRelocationPlanner,
    O = (),
    V = (),
> {
    loader: L,
    resolver: R,
    pipeline: LinkPipeline<'a, K, D>,
    relocator: Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD>,
    planner: P,
    observer: O,
    visible_modules: V,
    scratch_relocation_order: Vec<K>,
}

impl<'a, K, D> Linker<'a, K, D>
where
    K: Clone + Ord,
    D: Default + 'static,
{
    /// Creates a linker with an empty planning pipeline, default relocation
    /// hooks, and the default relocation planner.
    #[inline]
    pub fn new() -> Self {
        Self {
            loader: Loader::new().with_context(),
            resolver: (),
            pipeline: LinkPipeline::new(),
            relocator: Relocator::new(),
            planner: DefaultRelocationPlanner,
            observer: (),
            visible_modules: (),
            scratch_relocation_order: Vec::new(),
        }
    }
}

impl<'a, K, D> Default for Linker<'a, K, D>
where
    K: Clone + Ord,
    D: Default + 'static,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K, D, L, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, O, V>
    Linker<'a, K, D, L, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, O, V>
where
    K: Clone + Ord,
    D: 'static,
{
    /// Replaces the resolver used by link operations.
    pub fn resolver<NewR>(
        self,
        resolver: NewR,
    ) -> Linker<'a, K, D, L, NewR, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, O, V>
    {
        Linker {
            loader: self.loader,
            resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner: self.planner,
            observer: self.observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
        }
    }

    /// Transforms the relocation configuration.
    pub fn map_relocator<
        NewPreS,
        NewPostS,
        NewLazyPreS,
        NewLazyPostS,
        NewPreH,
        NewPostH,
        NewScopeD,
    >(
        self,
        configure: impl FnOnce(
            Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD>,
        ) -> Relocator<
            (),
            NewPreS,
            NewPostS,
            NewLazyPreS,
            NewLazyPostS,
            NewPreH,
            NewPostH,
            NewScopeD,
        >,
    ) -> Linker<
        'a,
        K,
        D,
        L,
        R,
        NewPreS,
        NewPostS,
        NewLazyPreS,
        NewLazyPostS,
        NewPreH,
        NewPostH,
        NewScopeD,
        P,
        O,
        V,
    > {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: configure(self.relocator),
            planner: self.planner,
            observer: self.observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
        }
    }

    /// Replaces the relocation planner.
    pub fn planner<NewP>(
        self,
        planner: NewP,
    ) -> Linker<'a, K, D, L, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, NewP, O, V>
    {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner,
            observer: self.observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
        }
    }

    /// Replaces the staged-load observer used by link operations.
    pub fn observer<NewO>(
        self,
        observer: NewO,
    ) -> Linker<'a, K, D, L, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, NewO, V>
    {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner: self.planner,
            observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
        }
    }

    /// Replaces the external visible-module overlay used by link operations.
    pub fn visible_modules<NewV>(
        self,
        visible_modules: NewV,
    ) -> Linker<'a, K, D, L, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, O, NewV>
    {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner: self.planner,
            observer: self.observer,
            visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
        }
    }

    /// Transforms the pre-map planning pipeline.
    pub fn map_pipeline(
        mut self,
        configure: impl FnOnce(LinkPipeline<'a, K, D>) -> LinkPipeline<'a, K, D>,
    ) -> Self {
        self.pipeline = configure(self.pipeline);
        self
    }
}

impl<'a, K, D, M, H, Tls, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, O, V>
    Linker<
        'a,
        K,
        D,
        Loader<M, H, D, Tls>,
        R,
        PreS,
        PostS,
        LazyPreS,
        LazyPostS,
        PreH,
        PostH,
        ScopeD,
        P,
        O,
        V,
    >
where
    K: Clone + Ord,
    D: 'static,
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
{
    /// Transforms the loader configuration.
    pub fn map_loader<NewM, NewH, NewTls>(
        self,
        configure: impl FnOnce(Loader<M, H, D, Tls>) -> Loader<NewM, NewH, D, NewTls>,
    ) -> Linker<
        'a,
        K,
        D,
        Loader<NewM, NewH, D, NewTls>,
        R,
        PreS,
        PostS,
        LazyPreS,
        LazyPostS,
        PreH,
        PostH,
        ScopeD,
        P,
        O,
        V,
    >
    where
        NewM: Mmap,
        NewH: LoadHook,
        NewTls: TlsResolver,
    {
        Linker {
            loader: configure(self.loader),
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner: self.planner,
            observer: self.observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
        }
    }
}

impl<'a, K, D, M, H, Tls, Resolver, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, O, V>
    Linker<
        'a,
        K,
        D,
        Loader<M, H, D, Tls>,
        Resolver,
        PreS,
        PostS,
        LazyPreS,
        LazyPostS,
        PreH,
        PostH,
        ScopeD,
        P,
        O,
        V,
    >
where
    K: Clone + Ord,
    D: Default + 'static,
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
    PreS: SymbolLookup + Clone,
    PostS: SymbolLookup + Clone,
    LazyPreS: SymbolLookup + Send + Sync + 'static + Clone,
    LazyPostS: SymbolLookup + Send + Sync + 'static + Clone,
    PreH: RelocationHandler + Clone,
    PostH: RelocationHandler + Clone,
    P: RelocationPlanner<K, D>,
    O: LoadObserver<K, D>,
    V: VisibleModules<K, D>,
{
    /// Loads one module through the legacy map-then-resolve path.
    ///
    /// Repeated calls reuse already-loaded entries in the same context. The
    /// context is mutated only after the current load succeeds.
    pub fn load<'cfg, Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        key: K,
    ) -> Result<LoadedCore<D>>
    where
        K: 'cfg,
        Meta: Default,
        Resolver: KeyResolver<'cfg, K, D, Meta>,
    {
        if let Some(loaded) = context.committed.get(&key) {
            return Ok(loaded.clone());
        }
        if let Some(loaded) = self.visible_modules.loaded(&key) {
            return Ok(loaded);
        }

        let prepared = Self::prepare_runtime_load(
            context,
            &key,
            &mut self.loader,
            &mut self.resolver,
            &mut self.observer,
            &self.visible_modules,
        )?;
        self.execute_prepared_load(context, prepared)
    }

    /// Discovers, plans, and loads one module through the scan-first path.
    pub fn load_scan_first<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        key: K,
    ) -> Result<LoadedCore<D>>
    where
        K: 'static,
        Meta: Default,
        Resolver: KeyResolver<'static, K, D, Meta>,
    {
        if let Some(loaded) = context.committed.get(&key) {
            return Ok(loaded.clone());
        }
        if let Some(loaded) = self.visible_modules.loaded(&key) {
            return Ok(loaded);
        }

        let prepared = match Self::prepare_scan_load(
            context,
            &key,
            &mut self.loader,
            &mut self.resolver,
            &mut self.pipeline,
            &self.visible_modules,
        )? {
            ScanDiscovery::Existing(root) => PreparedLoad::runtime(root, LoadSession::new()),
            ScanDiscovery::Plan(plan) => {
                Self::prepare_planned_load(plan, &mut self.loader, &mut self.observer)?
            }
        };
        self.execute_prepared_load(context, prepared)
    }

    fn prepare_runtime_load<'cfg, Meta>(
        context: &LinkContext<K, D, Meta>,
        key: &K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut Resolver,
        observer: &mut O,
        visible_modules: &V,
    ) -> Result<PreparedLoad<K, D>>
    where
        K: 'cfg,
        Resolver: KeyResolver<'cfg, K, D, Meta>,
    {
        let mut session = LoadSession::new();
        let mut resolve_context = LoadResolveContext::new(
            context.committed.view(),
            visible_modules,
            &mut session.resolve,
        );
        let root = resolve_context.stage_resolved(resolver.load_root(key)?, loader, observer)?;
        if resolve_context.contains_pending(&root) {
            resolve_context.resolve_dependency_graph(root.clone(), loader, resolver, observer)?;
        }

        Ok(PreparedLoad::runtime(root, session))
    }

    fn prepare_scan_load<Meta>(
        context: &LinkContext<K, D, Meta>,
        key: &K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut Resolver,
        pipeline: &mut LinkPipeline<'_, K, D>,
        visible_modules: &V,
    ) -> Result<ScanDiscovery<K, D>>
    where
        K: 'static,
        Resolver: KeyResolver<'static, K, D, Meta>,
    {
        let mut session = ResolveSession::new();
        let mut observer = ();
        let mut resolve_context =
            ScanResolveContext::new(context.committed.view(), visible_modules, &mut session);
        let root =
            resolve_context.stage_resolved(resolver.load_root(key)?, loader, &mut observer)?;
        if !resolve_context.contains_pending(&root) {
            return Ok(ScanDiscovery::Existing(root));
        }
        resolve_context.resolve_dependency_graph(root.clone(), loader, resolver, &mut observer)?;

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
        Ok(ScanDiscovery::Plan(plan))
    }

    fn prepare_planned_load(
        mut plan: LinkPlan<K, D>,
        loader: &mut Loader<M, H, D, Tls>,
        observer: &mut O,
    ) -> Result<PreparedLoad<K, D>> {
        // Scan discovery already seeded layout-side metadata before the pass pipeline ran.
        // The planned-load phase only needs to normalize materialization choices and rebuild
        // any derived addresses that those choices affect.
        let mut mapped_runtime = Self::prepare_mapped_runtime(&mut plan)?;

        let (root, group_order, entries, memory_layout) = plan.into_parts();
        let mut session = LoadSession::new();
        let mut module_keys = SecondaryMap::default();
        for (module_id, entry) in entries.iter() {
            let _ = module_keys.insert(module_id, entry.key().clone());
        }
        session.resolve.group_order = group_order
            .iter()
            .map(|module_id| module_keys[*module_id].clone())
            .collect();

        for (module_id, entry) in entries {
            let (key, module, direct_dep_ids) = entry.into_parts();
            let direct_deps = direct_dep_ids
                .iter()
                .map(|dep_id| module_keys[*dep_id].clone())
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let raw = Self::materialize_planned_raw(
                loader,
                &memory_layout,
                &mut mapped_runtime,
                module_id,
                module,
            )?;
            observer.on_staged_dylib(StagedDylib::new(&key, &raw))?;
            session.insert_resolved_pending(key, raw, direct_deps);
        }

        Ok(PreparedLoad::planned(
            module_keys[root].clone(),
            session,
            mapped_runtime,
        ))
    }

    fn prepare_mapped_runtime(
        plan: &mut LinkPlan<K, D>,
    ) -> Result<Option<mapped::MappedRuntimeMemory>> {
        materialization::normalize_plan(plan)?;
        let mut mapped_runtime = mapped::MappedRuntimeMemory::map::<M, _, _>(plan)?;

        if let Some(runtime) = mapped_runtime.as_mut() {
            let section_region_modules = plan
                .modules_with_materialization(Materialization::SectionRegions)
                .collect::<Vec<_>>();
            for module_id in section_region_modules {
                runtime.repair_module(module_id, plan)?;
            }
            runtime.populate(plan)?;
        }

        Ok(mapped_runtime)
    }

    fn materialize_planned_raw(
        loader: &mut Loader<M, H, D, Tls>,
        plan: &MemoryLayoutPlan,
        mapped_runtime: &mut Option<mapped::MappedRuntimeMemory>,
        module_id: ModuleId,
        scanned: ScannedDylib<D>,
    ) -> Result<RawDylib<D>> {
        match plan
            .materialization(module_id)
            .unwrap_or(Materialization::WholeDsoRegion)
        {
            Materialization::SectionRegions => {
                let runtime = mapped_runtime
                    .as_mut()
                    .ok_or_else(|| {
                        LinkerError::runtime_memory(
                            "section-region planned load is missing mapped runtime memory",
                        )
                    })?
                    .take_module(module_id)?;
                let (init_fn, fini_fn) = loader.inner.lifecycle_handlers();
                let mut raw = mapped::build_arena_raw_dylib::<D, Tls>(
                    scanned,
                    runtime,
                    init_fn.clone(),
                    fini_fn.clone(),
                    loader.inner.force_static_tls(),
                )?;
                loader.inner.post_load_dylib(&mut raw)?;
                Ok(raw)
            }
            Materialization::WholeDsoRegion => {
                let mut raw = loader.load_dylib_impl(scanned.into_reader())?;
                apply_section_overrides(&mut raw, module_id, plan);
                Ok(raw)
            }
        }
    }

    fn execute_prepared_load<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        prepared: PreparedLoad<K, D>,
    ) -> Result<LoadedCore<D>>
    where
        Meta: Default,
    {
        let PreparedLoad {
            root,
            mut session,
            mapped_runtime,
        } = prepared;

        if !session.resolve.entries.is_empty() {
            self.relocate_pending_modules(&root, context, &mut session)?;
        }

        if let Some(mapped_runtime) = mapped_runtime.as_ref() {
            mapped_runtime.protect::<M>()?;
        }

        Self::commit_session(context, &mut session);

        context
            .committed
            .get(&root)
            .cloned()
            .or_else(|| self.visible_modules.loaded(&root))
            .ok_or_else(|| LinkerError::context("load root missing after commit"))
            .map_err(Into::into)
    }

    /// Relocates every pending raw module reachable from `root`.
    ///
    /// Modules are relocated in post-order so dependencies are finalized before
    /// dependents. The relocation planner receives a [`RelocationRequest`]
    /// describing each key, raw module, and batch-start relocation scope.
    fn relocate_pending_modules<Meta>(
        &mut self,
        root: &K,
        context: &LinkContext<K, D, Meta>,
        session: &mut LoadSession<K, D>,
    ) -> Result<()> {
        let mut order = mem::take(&mut self.scratch_relocation_order);
        Self::build_relocation_order(root, &session.resolve.entries, &mut order);
        let scope = Self::build_group_scope(context, session, &self.visible_modules);

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
                let inputs = self.planner.plan(&req)?;
                let raw = req.into_raw();
                let loaded = self
                    .relocator
                    .clone()
                    .binding(inputs.binding())
                    .with_object(raw)
                    .scope(inputs.scope().iter())
                    .relocate()?;
                session.push_ready(key, (*loaded).clone(), direct_deps);
            }
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }

    fn build_relocation_order(
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

    fn build_group_scope<Meta>(
        context: &LinkContext<K, D, Meta>,
        session: &LoadSession<K, D>,
        visible_modules: &V,
    ) -> Arc<[LoadedCore<D>]>
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
                    context
                        .committed
                        .get(scope_key)
                        .cloned()
                        .or_else(|| visible_modules.loaded(scope_key))
                        .expect("scope key must resolve to a visible or pending module")
                }
            })
            .collect::<Vec<_>>()
            .into()
    }

    fn commit_session<Meta>(context: &mut LinkContext<K, D, Meta>, session: &mut LoadSession<K, D>)
    where
        Meta: Default,
    {
        let ready = mem::take(&mut session.ready_to_commit);
        for entry in ready {
            context.committed.insert_new(
                entry.key,
                CommittedEntry::new(entry.module, entry.direct_deps, Meta::default()),
            );
        }
    }
}

struct PreparedLoad<K, D: 'static> {
    root: K,
    session: LoadSession<K, D>,
    mapped_runtime: Option<mapped::MappedRuntimeMemory>,
}

enum ScanDiscovery<K, D: 'static> {
    Existing(K),
    Plan(LinkPlan<K, D>),
}

impl<K, D: 'static> PreparedLoad<K, D> {
    fn runtime(root: K, session: LoadSession<K, D>) -> Self {
        Self {
            root,
            session,
            mapped_runtime: None,
        }
    }

    fn planned(
        root: K,
        session: LoadSession<K, D>,
        mapped_runtime: Option<mapped::MappedRuntimeMemory>,
    ) -> Self {
        Self {
            root,
            session,
            mapped_runtime,
        }
    }
}

fn apply_section_overrides<D>(raw: &mut RawDylib<D>, module_id: ModuleId, plan: &MemoryLayoutPlan) {
    let module = plan.module(module_id);
    let segments = raw.core_ref().segments();

    for section_id in module.alloc_sections().iter().copied() {
        if !plan.section_is_override(section_id) {
            continue;
        }
        let metadata = plan.section(section_id);
        let data = plan
            .data(section_id)
            .expect("missing section data for planned override");
        let dst = segments.get_slice_mut::<u8>(metadata.source_address(), metadata.size());
        assert_eq!(
            data.len(),
            dst.len(),
            "planned section override size does not match the loaded section"
        );
        dst.copy_from_slice(data.as_ref());
    }
}
