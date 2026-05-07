use super::{
    context::LinkContext,
    layout::{Materialization, MemoryLayoutPlan},
    mapped, materialization,
    passes::LinkPipeline,
    plan::{LinkPlan, ModuleId},
    request::{
        DefaultRelocationPlanner, LoadObserver, RelocationPlanner, RelocationRequest,
        StagedDynamic, VisibleModules,
    },
    resolve::{KeyResolver, LoadResolveContext, ScanResolveContext},
    session::{GraphEntry, LoadSession, ResolveSession},
    storage::CommittedEntry,
};
use crate::{
    LinkerError, Loader, Result,
    entity::SecondaryMap,
    image::{LoadedCore, RawDynamic, ScannedDynamic},
    loader::LoadHook,
    os::{DefaultMmap, Mmap},
    relocation::{
        RelocationArch, RelocationHandler, RelocationValueProvider, Relocator, SymbolLookup,
    },
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{marker::PhantomData, mem};

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
    L = Loader<DefaultMmap, (), (), ()>,
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
    pipeline: LinkPipeline<'a, K>,
    relocator: Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD>,
    planner: P,
    observer: O,
    visible_modules: V,
    scratch_relocation_order: Vec<K>,
    _marker: PhantomData<fn() -> D>,
}

impl<'a, K> Linker<'a, K, ()>
where
    K: Clone + Ord,
{
    /// Creates a linker with an empty planning pipeline, default relocation
    /// hooks, and the default relocation planner.
    ///
    /// The linker starts in the `D = ()` builder phase, mirroring
    /// [`Loader::new`]. Switch to a custom user-data type with
    /// [`Linker::with_dynamic_initializer`] after configuring the loader
    /// (including [`Loader::for_arch`] via [`Linker::map_loader`]).
    #[inline]
    pub fn new() -> Self {
        Self {
            loader: Loader::new(),
            resolver: (),
            pipeline: LinkPipeline::new(),
            relocator: Relocator::new(),
            planner: DefaultRelocationPlanner,
            observer: (),
            visible_modules: (),
            scratch_relocation_order: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<'a, K> Default for Linker<'a, K, ()>
where
    K: Clone + Ord,
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
            _marker: self._marker,
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
            _marker: self._marker,
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
            _marker: self._marker,
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
            _marker: self._marker,
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
            _marker: self._marker,
        }
    }

    /// Transforms the pre-map planning pipeline.
    pub fn map_pipeline(
        mut self,
        configure: impl FnOnce(LinkPipeline<'a, K>) -> LinkPipeline<'a, K>,
    ) -> Self {
        self.pipeline = configure(self.pipeline);
        self
    }
}

impl<'a, K, D, M, H, Tls, Arch, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, O, V>
    Linker<
        'a,
        K,
        D,
        Loader<M, H, D, Tls, Arch>,
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
    Arch: RelocationArch,
{
    /// Transforms the loader configuration.
    ///
    /// The closure may switch any of the loader's type parameters,
    /// including the user-data type `D` and the relocation backend `Arch`.
    /// When `D` changes, the linker's own `D` follows: a closure that
    /// returns `Loader<.., NewD, .., NewArch>` produces a
    /// `Linker<.., NewD, ..>` whose subsequent
    /// [`load`](Linker::load) calls yield `LoadedCore<NewD>`.
    ///
    /// Because [`Loader::for_arch`] is only available while the loader is
    /// in its `D = ()` builder phase, the typical cross-architecture flow
    /// is to start from a `Linker::<K>::new()` (which seeds `D = ()`),
    /// then in this closure call `for_arch::<NewArch>()` *before*
    /// [`with_dynamic_initializer`](Loader::with_dynamic_initializer):
    ///
    /// ```ignore
    /// let linker = Linker::<&'static str>::new()
    ///     .map_loader(|loader| {
    ///         loader
    ///             .for_arch::<X86_64Arch>()
    ///             .with_dynamic_initializer::<MyData>(|raw| {
    ///                 // populate user data from the relocated image
    ///                 Ok(())
    ///             })
    ///     });
    /// ```
    pub fn map_loader<NewM, NewH, NewD, NewTls, NewArch>(
        self,
        configure: impl FnOnce(Loader<M, H, D, Tls, Arch>) -> Loader<NewM, NewH, NewD, NewTls, NewArch>,
    ) -> Linker<
        'a,
        K,
        NewD,
        Loader<NewM, NewH, NewD, NewTls, NewArch>,
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
        NewD: 'static,
        NewTls: TlsResolver,
        NewArch: RelocationArch,
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
            _marker: PhantomData,
        }
    }
}

impl<
    'a,
    K,
    D,
    M,
    H,
    Tls,
    Arch,
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
    Linker<
        'a,
        K,
        D,
        Loader<M, H, D, Tls, Arch>,
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
    Arch: RelocationArch,
    PreS: SymbolLookup + Clone,
    PostS: SymbolLookup + Clone,
    LazyPreS: SymbolLookup + Send + Sync + 'static + Clone,
    LazyPostS: SymbolLookup + Send + Sync + 'static + Clone,
    PreH: RelocationHandler + Clone,
    PostH: RelocationHandler + Clone,
    P: RelocationPlanner<K, D, Arch>,
    O: LoadObserver<K, D, Arch>,
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
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
            return Ok(loaded);
        }

        let prepared = Self::prepare_runtime_load(
            context,
            &mut self.loader,
            &mut self.resolver,
            &mut self.observer,
            &self.visible_modules,
            |context, visible_modules, session, loader, resolver, observer| {
                let mut resolve_context = LoadResolveContext::new(
                    context.committed.view(),
                    visible_modules,
                    &mut session.resolve,
                );
                resolve_context.stage_resolved(resolver.load_root(&key)?, loader, observer)
            },
        )?;
        self.execute_prepared_load(context, prepared)
    }

    /// Resolves dependencies and relocates a root dynamic image that has
    /// already been mapped by the caller.
    pub fn load_mapped_root<'cfg, Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        key: K,
        raw: RawDynamic<D, Arch>,
    ) -> Result<LoadedCore<D>>
    where
        K: 'cfg,
        Meta: Default,
        Resolver: KeyResolver<'cfg, K, D, Meta>,
    {
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
            return Ok(loaded);
        }

        let prepared = Self::prepare_runtime_load(
            context,
            &mut self.loader,
            &mut self.resolver,
            &mut self.observer,
            &self.visible_modules,
            move |_, _, session, _, _, observer| {
                observer.on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
                session.resolve.insert_entry(key.clone(), raw);
                Ok(key)
            },
        )?;
        self.execute_prepared_load(context, prepared)
    }

    /// Discovers, plans, and loads one module through the scan-first path.
    #[allow(private_bounds)]
    pub fn load_scan_first<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        key: K,
    ) -> Result<LoadedCore<D>>
    where
        K: 'static,
        Meta: Default,
        Resolver: KeyResolver<'static, K, D, Meta>,
        Arch: RelocationValueProvider + mapped::GotPltTarget,
    {
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
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

    fn prepare_runtime_load<'cfg, Meta, Seed>(
        context: &LinkContext<K, D, Meta>,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut Resolver,
        observer: &mut O,
        visible_modules: &V,
        seed_root: Seed,
    ) -> Result<PreparedLoad<K, D, Arch>>
    where
        K: 'cfg,
        Resolver: KeyResolver<'cfg, K, D, Meta>,
        Seed: FnOnce(
            &LinkContext<K, D, Meta>,
            &V,
            &mut LoadSession<K, D, Arch>,
            &mut Loader<M, H, D, Tls, Arch>,
            &mut Resolver,
            &mut O,
        ) -> Result<K>,
    {
        let mut session = LoadSession::new();
        let root = seed_root(
            context,
            visible_modules,
            &mut session,
            loader,
            resolver,
            observer,
        )?;
        let mut resolve_context = LoadResolveContext::new(
            context.committed.view(),
            visible_modules,
            &mut session.resolve,
        );
        if resolve_context.contains_pending(&root) {
            resolve_context.resolve_dependency_graph(root.clone(), loader, resolver, observer)?;
        }

        Ok(PreparedLoad::runtime(root, session))
    }

    fn prepare_scan_load<Meta>(
        context: &LinkContext<K, D, Meta>,
        key: &K,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut Resolver,
        pipeline: &mut LinkPipeline<'_, K>,
        visible_modules: &V,
    ) -> Result<ScanDiscovery<K>>
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
        mut plan: LinkPlan<K>,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        observer: &mut O,
    ) -> Result<PreparedLoad<K, D, Arch>>
    where
        Arch: RelocationValueProvider + mapped::GotPltTarget,
    {
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
            observer.on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
            session.insert_resolved_pending(key, raw, direct_deps);
        }

        Ok(PreparedLoad::planned(
            module_keys[root].clone(),
            session,
            mapped_runtime,
        ))
    }

    fn prepare_mapped_runtime(plan: &mut LinkPlan<K>) -> Result<Option<mapped::MappedRuntimeMemory>>
    where
        Arch: RelocationValueProvider + mapped::GotPltTarget,
    {
        materialization::normalize_plan(plan)?;
        let mut mapped_runtime = mapped::MappedRuntimeMemory::map::<M, _>(plan)?;

        if let Some(runtime) = mapped_runtime.as_mut() {
            let section_region_modules = plan
                .modules_with_materialization(Materialization::SectionRegions)
                .collect::<Vec<_>>();
            for module_id in section_region_modules {
                runtime.repair_module::<_, Arch>(module_id, plan)?;
            }
            runtime.populate(plan)?;
        }

        Ok(mapped_runtime)
    }

    fn materialize_planned_raw(
        loader: &mut Loader<M, H, D, Tls, Arch>,
        plan: &MemoryLayoutPlan,
        mapped_runtime: &mut Option<mapped::MappedRuntimeMemory>,
        module_id: ModuleId,
        scanned: ScannedDynamic,
    ) -> Result<RawDynamic<D, Arch>> {
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
                let mut raw = mapped::build_arena_raw_dynamic::<D, Tls, Arch>(
                    scanned,
                    runtime,
                    init_fn.clone(),
                    fini_fn.clone(),
                    loader.inner.force_static_tls(),
                )?;
                loader.inner.initialize_dynamic(&mut raw)?;
                Ok(raw)
            }
            Materialization::WholeDsoRegion => {
                let mut raw = loader.load_scanned_dynamic_raw_impl(scanned)?;
                apply_section_overrides(&mut raw, module_id, plan);
                loader.inner.initialize_dynamic(&mut raw)?;
                Ok(raw)
            }
        }
    }

    fn execute_prepared_load<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        prepared: PreparedLoad<K, D, Arch>,
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

        visible_loaded(context, &self.visible_modules, &root)
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
        session: &mut LoadSession<K, D, Arch>,
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
                let (scope, binding) = inputs.into_parts();
                let loaded = self
                    .relocator
                    .clone()
                    .binding(binding)
                    .with_object(raw)
                    .shared_scope(scope)
                    .relocate()?;
                session.push_ready(key, loaded, direct_deps);
            }
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }

    fn build_relocation_order(
        root: &K,
        pending: &BTreeMap<K, GraphEntry<K, RawDynamic<D, Arch>>>,
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
        session: &LoadSession<K, D, Arch>,
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
                    visible_loaded(context, visible_modules, scope_key)
                        .expect("scope key must resolve to a visible or pending module")
                }
            })
            .collect::<Vec<_>>()
            .into()
    }

    fn commit_session<Meta>(
        context: &mut LinkContext<K, D, Meta>,
        session: &mut LoadSession<K, D, Arch>,
    ) where
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

struct PreparedLoad<K, D: 'static, Arch: RelocationArch> {
    root: K,
    session: LoadSession<K, D, Arch>,
    mapped_runtime: Option<mapped::MappedRuntimeMemory>,
}

enum ScanDiscovery<K> {
    Existing(K),
    Plan(LinkPlan<K>),
}

impl<K, D: 'static, Arch: RelocationArch> PreparedLoad<K, D, Arch> {
    fn runtime(root: K, session: LoadSession<K, D, Arch>) -> Self {
        Self {
            root,
            session,
            mapped_runtime: None,
        }
    }

    fn planned(
        root: K,
        session: LoadSession<K, D, Arch>,
        mapped_runtime: Option<mapped::MappedRuntimeMemory>,
    ) -> Self {
        Self {
            root,
            session,
            mapped_runtime,
        }
    }
}

fn apply_section_overrides<D, Arch: RelocationArch>(
    raw: &mut RawDynamic<D, Arch>,
    module_id: ModuleId,
    plan: &MemoryLayoutPlan,
) {
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

#[inline]
fn visible_loaded<K, D, Meta, V>(
    context: &LinkContext<K, D, Meta>,
    visible_modules: &V,
    key: &K,
) -> Option<LoadedCore<D>>
where
    K: Clone + Ord,
    D: 'static,
    V: VisibleModules<K, D>,
{
    context
        .committed
        .get(key)
        .cloned()
        .or_else(|| visible_modules.loaded(key))
}
