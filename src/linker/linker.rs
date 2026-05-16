use super::{
    context::LinkContext,
    request::{
        DefaultRelocationPlanner, LoadObserver, RelocationPlanner, RelocationRequest,
        StagedDynamic, VisibleModules,
    },
    resolve::{LoadResolveContext, ScanResolveContext},
    resolver::KeyResolver,
    scan::{
        GotPltTarget, LinkPipeline, LinkPlan, MappedRuntimeMemory, Materialization,
        MemoryLayoutPlan, ModuleId, build_arena_raw_dynamic, normalize_plan,
    },
    session::{GraphEntry, LoadSession},
    storage::KeyId,
};
use crate::{
    LinkerError, Loader, Result,
    entity::SecondaryMap,
    image::{LoadedCore, ModuleHandle, ModuleScope, RawDynamic, ScannedDynamic},
    linker::session::ResolveSession,
    loader::LoadHook,
    os::{DefaultMmap, Mmap},
    relocation::{RelocationArch, RelocationHandler, Relocator},
    tls::TlsResolver,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{marker::PhantomData, mem, ops::Deref};

/// Result of a successful linker load operation.
///
/// `committed` contains the newly committed modules' [`KeyId`] values in load
/// order.
#[derive(Debug)]
pub struct LoadResult<D: 'static, Arch: RelocationArch = crate::arch::NativeArch> {
    root: LoadedCore<D, Arch>,
    committed: Box<[KeyId]>,
}

impl<D: 'static, Arch> LoadResult<D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(root: LoadedCore<D, Arch>, committed: Box<[KeyId]>) -> Self {
        Self { root, committed }
    }

    /// Returns the loaded root module.
    #[inline]
    pub fn root(&self) -> &LoadedCore<D, Arch> {
        &self.root
    }

    /// Returns module ids committed by this load operation in load order.
    #[inline]
    pub fn committed(&self) -> &[KeyId] {
        &self.committed
    }

    /// Consumes the result and returns the loaded root module.
    #[inline]
    pub fn into_root(self) -> LoadedCore<D, Arch> {
        self.root
    }
}

impl<D: 'static, Arch> Deref for LoadResult<D, Arch>
where
    Arch: RelocationArch,
{
    type Target = LoadedCore<D, Arch>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.root
    }
}

/// Configurable front-end for runtime dependency discovery and relocation.
///
/// `Linker` stores one relocation domain: all modules committed through one
/// context use the same [`RelocationArch`].
pub struct Linker<
    'a,
    K: Clone + Ord,
    D: 'static,
    Arch: RelocationArch = crate::arch::NativeArch,
    L = Loader<DefaultMmap, (), (), (), Arch>,
    R = (),
    PreH = (),
    PostH = (),
    P = DefaultRelocationPlanner,
    O = (),
    V = (),
> {
    loader: L,
    resolver: R,
    pipeline: LinkPipeline<'a, K, Arch>,
    relocator: Relocator<(), PreH, PostH, (), Arch>,
    planner: P,
    observer: O,
    visible_modules: V,
    scratch_relocation_order: Vec<KeyId>,
    _marker: PhantomData<fn() -> (D, Arch)>,
}

impl<'a, K> Linker<'a, K, ()>
where
    K: Clone + Ord,
{
    /// Creates a linker using the default loader and native target architecture.
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

    /// Switch the linker's relocation domain before a loader is attached.
    ///
    /// This mirrors [`Loader::for_arch`] for the dependency-linking front-end:
    /// all modules committed through the resulting [`LinkContext`] use
    /// `NewArch`.
    #[inline]
    pub fn for_arch<NewArch>(
        self,
    ) -> Linker<
        'a,
        K,
        (),
        NewArch,
        Loader<DefaultMmap, (), (), (), NewArch>,
        (),
        (),
        (),
        DefaultRelocationPlanner,
        (),
        (),
    >
    where
        NewArch: RelocationArch,
    {
        Linker {
            loader: self.loader.for_arch::<NewArch>(),
            resolver: (),
            pipeline: LinkPipeline::new(),
            relocator: self.relocator.for_arch::<NewArch>(),
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

impl<'a, K, D, L, R, PreH, PostH, P, O, V, Arch> Linker<'a, K, D, Arch, L, R, PreH, PostH, P, O, V>
where
    K: Clone + Ord,
    D: 'static,
    Arch: RelocationArch,
{
    /// Sets the key resolver used to resolve root keys and dependencies.
    pub fn resolver<NewR>(
        self,
        resolver: NewR,
    ) -> Linker<'a, K, D, Arch, L, NewR, PreH, PostH, P, O, V> {
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

    /// Reconfigures the relocator template used for loaded modules.
    pub fn map_relocator<NewPreH, NewPostH>(
        self,
        configure: impl FnOnce(
            Relocator<(), PreH, PostH, (), Arch>,
        ) -> Relocator<(), NewPreH, NewPostH, (), Arch>,
    ) -> Linker<'a, K, D, Arch, L, R, NewPreH, NewPostH, P, O, V> {
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

    /// Sets the relocation planner used after dependency discovery.
    pub fn planner<NewP>(
        self,
        planner: NewP,
    ) -> Linker<'a, K, D, Arch, L, R, PreH, PostH, NewP, O, V> {
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

    /// Sets the load observer used during staging and materialization.
    pub fn observer<NewO>(
        self,
        observer: NewO,
    ) -> Linker<'a, K, D, Arch, L, R, PreH, PostH, P, NewO, V> {
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

    /// Sets additional modules that are visible for reuse or lookup.
    pub fn visible_modules<NewV>(
        self,
        visible_modules: NewV,
    ) -> Linker<'a, K, D, Arch, L, R, PreH, PostH, P, O, NewV> {
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

    /// Reconfigures the scan-first pipeline.
    pub fn map_pipeline(
        mut self,
        configure: impl FnOnce(LinkPipeline<'a, K, Arch>) -> LinkPipeline<'a, K, Arch>,
    ) -> Self {
        self.pipeline = configure(self.pipeline);
        self
    }
}

impl<'a, K, D, M, H, Tls, Arch, R, PreH, PostH, P, O, V>
    Linker<'a, K, D, Arch, Loader<M, H, D, Tls, Arch>, R, PreH, PostH, P, O, V>
where
    K: Clone + Ord,
    D: 'static,
    M: Mmap,
    H: LoadHook<Arch::Layout>,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    /// Reconfigures the underlying loader.
    pub fn map_loader<NewM, NewH, NewD, NewTls>(
        self,
        configure: impl FnOnce(Loader<M, H, D, Tls, Arch>) -> Loader<NewM, NewH, NewD, NewTls, Arch>,
    ) -> Linker<'a, K, NewD, Arch, Loader<NewM, NewH, NewD, NewTls, Arch>, R, PreH, PostH, P, O, V>
    where
        NewM: Mmap,
        NewH: LoadHook<Arch::Layout>,
        NewD: 'static,
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
            _marker: PhantomData,
        }
    }
}

#[allow(private_bounds)]
impl<'a, K, D, M, H, Tls, Arch, Resolver, PreH, PostH, P, O, V>
    Linker<'a, K, D, Arch, Loader<M, H, D, Tls, Arch>, Resolver, PreH, PostH, P, O, V>
where
    K: Clone + Ord,
    D: Default + 'static,
    M: Mmap,
    H: LoadHook<Arch::Layout>,
    Tls: TlsResolver,
    Arch: RelocationArch + crate::relocation::RelocationValueProvider + GotPltTarget,
    crate::elf::ElfRelType<Arch>: crate::ByteRepr,
    PreH: RelocationHandler<Arch> + Clone,
    PostH: RelocationHandler<Arch> + Clone,
    P: RelocationPlanner<K, D, Arch>,
    O: LoadObserver<K, D, Arch>,
    V: VisibleModules<K, D, Arch>,
{
    /// Loads one module into this linker's relocation domain.
    pub fn load<'cfg, Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        key: K,
    ) -> Result<LoadResult<D, Arch>>
    where
        K: 'cfg,
        Meta: Default,
        Resolver: KeyResolver<'cfg, K>,
    {
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
            return Ok(LoadResult::new(loaded, Vec::new().into_boxed_slice()));
        }

        let prepared = self.prepare_runtime_load(
            context,
            |context, visible_modules, session, loader, resolver, observer| {
                let mut resolve_context = LoadResolveContext::new(
                    &mut context.committed,
                    visible_modules,
                    &mut session.resolve,
                );
                let resolved = resolve_context.resolve_root(&key, resolver)?;
                resolve_context.stage_resolved(resolved, loader, observer)
            },
        )?;
        self.execute_prepared_load(context, prepared)
    }

    /// Loads a pre-mapped root dynamic image and resolves its dependencies.
    pub fn load_mapped_root<'cfg, Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        key: K,
        raw: RawDynamic<D, Arch>,
    ) -> Result<LoadResult<D, Arch>>
    where
        K: 'cfg,
        Meta: Default,
        Resolver: KeyResolver<'cfg, K>,
    {
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
            return Ok(LoadResult::new(loaded, Vec::new().into_boxed_slice()));
        }

        let prepared =
            self.prepare_runtime_load(context, move |context, _, session, _, _, observer| {
                observer.on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
                let id = context.committed.intern_key(key.clone());
                session.resolve.insert_entry(id, raw);
                Ok(id)
            })?;
        self.execute_prepared_load(context, prepared)
    }

    /// Discovers, plans, and loads one module through the scan-first path.
    pub fn load_scan_first<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        key: K,
    ) -> Result<LoadResult<D, Arch>>
    where
        K: 'static,
        Meta: Default,
        Resolver: KeyResolver<'static, K>,
    {
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
            return Ok(LoadResult::new(loaded, Vec::new().into_boxed_slice()));
        }

        let prepared = match self.prepare_scan_load(context, &key)? {
            ScanDiscovery::Existing(root) => PreparedLoad::runtime(root, LoadSession::new()),
            ScanDiscovery::Plan(plan) => self.prepare_planned_load(context, plan)?,
        };
        self.execute_prepared_load(context, prepared)
    }

    fn prepare_scan_load<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        key: &K,
    ) -> Result<ScanDiscovery<K, Arch>>
    where
        K: 'static,
        Resolver: KeyResolver<'static, K>,
    {
        let mut session = ResolveSession::new();

        let mut resolve_context =
            ScanResolveContext::new(&mut context.committed, &self.visible_modules, &mut session);
        let resolved = resolve_context.resolve_root(key, &mut self.resolver)?;
        let root = resolve_context.stage_resolved(resolved, &mut self.loader)?;
        if !resolve_context.contains_pending(root) {
            return Ok(ScanDiscovery::Existing(root));
        }
        resolve_context.resolve_dependency_graph(root, &mut self.loader, &mut self.resolver)?;

        let ResolveSession {
            entries,
            group_order,
        } = session;
        let root_key = context
            .key(root)
            .expect("scan root id must resolve to an interned key")
            .clone();
        let group_order = group_order
            .into_iter()
            .map(|id| {
                context
                    .key(id)
                    .expect("scan group id must resolve to an interned key")
                    .clone()
            })
            .collect::<Vec<_>>();
        let mut plan = LinkPlan::new(
            root_key,
            group_order,
            entries
                .into_iter()
                .map(|(id, entry)| {
                    let key = context
                        .key(id)
                        .expect("scan entry id must resolve to an interned key")
                        .clone();
                    let direct_deps = entry
                        .direct_deps
                        .expect("missing resolved dependencies while building scan plan")
                        .into_vec()
                        .into_iter()
                        .map(|dep| {
                            context
                                .key(dep)
                                .expect("scan dependency id must resolve to an interned key")
                                .clone()
                        })
                        .collect::<Vec<_>>()
                        .into_boxed_slice();
                    (key, (entry.payload, direct_deps))
                })
                .collect(),
        );
        self.pipeline.run(&mut plan)?;
        Ok(ScanDiscovery::Plan(plan))
    }

    fn prepare_planned_load<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        mut plan: LinkPlan<K, Arch>,
    ) -> Result<PreparedLoad<D, Arch>> {
        let mut mapped_runtime = self.prepare_mapped_runtime(&mut plan)?;

        let (root, group_order, entries, memory_layout) = plan.into_parts();
        let mut session = LoadSession::new();
        let mut module_ids = SecondaryMap::default();
        for (module_id, entry) in entries.iter() {
            let id = context.committed.intern_key(entry.key().clone());
            let _ = module_ids.insert(module_id, id);
        }
        session.resolve.group_order = group_order
            .iter()
            .map(|module_id| module_ids[*module_id])
            .collect();

        for (module_id, entry) in entries {
            let (key, module, dep_ids) = entry.into_parts();
            let id = module_ids[module_id];
            let direct_deps = dep_ids
                .iter()
                .map(|dep_id| module_ids[*dep_id])
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let raw = self.materialize_planned_raw(
                &memory_layout,
                &mut mapped_runtime,
                module_id,
                module,
            )?;
            self.observer
                .on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
            session.insert_resolved_pending(id, raw, direct_deps);
        }

        Ok(PreparedLoad::planned(
            module_ids[root],
            session,
            mapped_runtime,
        ))
    }

    fn prepare_mapped_runtime(
        &mut self,
        plan: &mut LinkPlan<K, Arch>,
    ) -> Result<Option<MappedRuntimeMemory>> {
        normalize_plan(plan)?;
        let mut mapped_runtime = MappedRuntimeMemory::map::<M, _, Arch>(plan)?;

        if let Some(runtime) = mapped_runtime.as_mut() {
            let section_region_modules = plan
                .modules_with_materialization(Materialization::SectionRegions)
                .collect::<Vec<_>>();
            for module_id in section_region_modules {
                self.repair_planned_module(runtime, module_id, plan)?;
            }
            runtime.populate(plan)?;
        }

        Ok(mapped_runtime)
    }

    fn repair_planned_module(
        &mut self,
        runtime: &mut MappedRuntimeMemory,
        module_id: ModuleId,
        plan: &mut LinkPlan<K, Arch>,
    ) -> Result<()> {
        runtime.repair_module::<_, Arch>(module_id, plan)
    }

    fn materialize_planned_raw(
        &mut self,
        plan: &MemoryLayoutPlan,
        mapped_runtime: &mut Option<MappedRuntimeMemory>,
        module_id: ModuleId,
        scanned: ScannedDynamic<Arch>,
    ) -> Result<RawDynamic<D, Arch>> {
        match plan
            .materialization(module_id)
            .unwrap_or(Materialization::WholeDsoRegion)
        {
            Materialization::SectionRegions => {
                self.materialize_arena_raw(mapped_runtime, module_id, scanned)
            }
            Materialization::WholeDsoRegion => {
                let mut raw = self.loader.load_scanned_dynamic(scanned)?;
                apply_section_overrides(&mut raw, module_id, plan);
                Ok(raw)
            }
        }
    }

    fn materialize_arena_raw(
        &mut self,
        mapped_runtime: &mut Option<MappedRuntimeMemory>,
        module_id: ModuleId,
        scanned: ScannedDynamic<Arch>,
    ) -> Result<RawDynamic<D, Arch>> {
        let runtime = mapped_runtime
            .as_mut()
            .ok_or_else(|| {
                LinkerError::runtime_memory(
                    "section-region planned load is missing mapped runtime memory",
                )
            })?
            .take_module(module_id)?;
        let (init_fn, fini_fn) = self.loader.inner.lifecycle_handlers();
        let force_static_tls = self.loader.inner.force_static_tls();

        let mut raw = build_arena_raw_dynamic::<D, Tls, Arch>(
            scanned,
            runtime,
            init_fn,
            fini_fn,
            force_static_tls,
        )?;
        self.loader.inner.initialize_dynamic(&mut raw)?;
        Ok(raw)
    }

    fn prepare_runtime_load<'cfg, Meta, Seed>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        seed_root: Seed,
    ) -> Result<PreparedLoad<D, Arch>>
    where
        K: 'cfg,
        Resolver: KeyResolver<'cfg, K>,
        Seed: FnOnce(
            &mut LinkContext<K, D, Meta, Arch>,
            &V,
            &mut LoadSession<D, Arch>,
            &mut Loader<M, H, D, Tls, Arch>,
            &mut Resolver,
            &mut O,
        ) -> Result<KeyId>,
    {
        let mut session = LoadSession::new();
        let root = seed_root(
            context,
            &self.visible_modules,
            &mut session,
            &mut self.loader,
            &mut self.resolver,
            &mut self.observer,
        )?;
        let mut resolve_context = LoadResolveContext::new(
            &mut context.committed,
            &self.visible_modules,
            &mut session.resolve,
        );
        if resolve_context.contains_pending(root) {
            resolve_context.resolve_dependency_graph(
                root,
                &mut self.loader,
                &mut self.resolver,
                &mut self.observer,
            )?;
        }

        Ok(PreparedLoad::runtime(root, session))
    }

    fn execute_prepared_load<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        prepared: PreparedLoad<D, Arch>,
    ) -> Result<LoadResult<D, Arch>>
    where
        Meta: Default,
    {
        let PreparedLoad {
            root,
            mut session,
            mapped_runtime,
        } = prepared;

        if !session.resolve.entries.is_empty() {
            self.relocate_pending_modules(root, context, &mut session)?;
        }

        if let Some(mapped_runtime) = mapped_runtime.as_ref() {
            mapped_runtime.protect::<M>()?;
        }

        let committed = Self::commit_session(context, &mut session);

        let root = visible_module(context, &self.visible_modules, root)
            .and_then(|module| module.as_loaded::<D>().cloned())
            .ok_or_else(|| LinkerError::context("load root missing after commit"))?;
        Ok(LoadResult::new(root, committed))
    }

    fn relocate_pending_modules<Meta>(
        &mut self,
        root: KeyId,
        context: &LinkContext<K, D, Meta, Arch>,
        session: &mut LoadSession<D, Arch>,
    ) -> Result<()> {
        let mut order = mem::take(&mut self.scratch_relocation_order);
        Self::build_relocation_order(root, &session.resolve.entries, &mut order);
        let scope = Self::build_group_scope(context, session, &self.visible_modules);

        let result = (|| {
            for id in order.drain(..) {
                let entry = session
                    .resolve
                    .entries
                    .remove(&id)
                    .expect("missing pending module while relocating");
                let direct_deps = entry
                    .direct_deps
                    .expect("missing resolved dependencies while relocating");
                let key = context
                    .key(id)
                    .expect("pending module id must resolve to an interned key")
                    .clone();
                let req = RelocationRequest::new(&key, entry.payload, &scope);
                let inputs = self.planner.plan(&req)?;
                let raw = req.into_raw();
                let (scope, binding) = inputs.into_parts();
                let loaded = self
                    .relocator
                    .clone()
                    .with_object(raw)
                    .shared_scope(scope)
                    .binding(binding)
                    .relocate()?;
                session.push_ready(id, loaded, direct_deps);
            }
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }

    fn build_relocation_order(
        root: KeyId,
        pending: &BTreeMap<KeyId, GraphEntry<RawDynamic<D, Arch>>>,
        order: &mut Vec<KeyId>,
    ) {
        order.clear();
        if order.capacity() < pending.len() {
            order.reserve(pending.len() - order.capacity());
        }
        let mut visited = BTreeSet::new();
        let mut stack = Vec::with_capacity(pending.len().saturating_mul(2));
        stack.push((root, false));

        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                order.push(id);
                continue;
            }

            if !visited.insert(id) {
                continue;
            }

            let Some(slot) = pending.get(&id) else {
                continue;
            };

            stack.push((id, true));
            let direct_deps = slot
                .direct_deps
                .as_deref()
                .expect("missing resolved dependencies while building relocation order");
            for dep in direct_deps.iter().rev().copied() {
                stack.push((dep, false));
            }
        }
    }

    fn build_group_scope<Meta>(
        context: &LinkContext<K, D, Meta, Arch>,
        session: &LoadSession<D, Arch>,
        visible_modules: &V,
    ) -> ModuleScope<Arch>
    where
        K: Ord,
    {
        let modules = session
            .resolve
            .group_order
            .iter()
            .map(|id| {
                if let Some(entry) = session.resolve.entries.get(id) {
                    let module = unsafe { LoadedCore::from_core(entry.payload.core()) };
                    ModuleHandle::from(module)
                } else {
                    visible_module(context, visible_modules, *id)
                        .expect("scope key must resolve to a visible or pending module")
                }
            })
            .collect::<Vec<_>>();
        ModuleScope::from(modules)
    }

    fn commit_session<Meta>(
        context: &mut LinkContext<K, D, Meta, Arch>,
        session: &mut LoadSession<D, Arch>,
    ) -> Box<[KeyId]>
    where
        Meta: Default,
    {
        let mut ready = mem::take(&mut session.ready_to_commit);
        let mut committed = Vec::with_capacity(ready.len());
        for id in session.resolve.group_order.iter().copied() {
            let Some(entry) = ready.remove(&id) else {
                continue;
            };
            context
                .committed
                .insert_new_id(id, entry.module, entry.direct_deps, Meta::default());
            committed.push(id);
        }
        assert!(
            ready.is_empty(),
            "ready commit entries must all be present in group_order"
        );
        committed.into_boxed_slice()
    }
}

struct PreparedLoad<D: 'static, Arch: RelocationArch> {
    root: KeyId,
    session: LoadSession<D, Arch>,
    mapped_runtime: Option<MappedRuntimeMemory>,
}

enum ScanDiscovery<K, Arch: RelocationArch> {
    Existing(KeyId),
    Plan(LinkPlan<K, Arch>),
}

impl<D: 'static, Arch: RelocationArch> PreparedLoad<D, Arch> {
    fn runtime(root: KeyId, session: LoadSession<D, Arch>) -> Self {
        Self {
            root,
            session,
            mapped_runtime: None,
        }
    }

    fn planned(
        root: KeyId,
        session: LoadSession<D, Arch>,
        mapped_runtime: Option<MappedRuntimeMemory>,
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
fn visible_loaded<K, D, Meta, V, Arch>(
    context: &LinkContext<K, D, Meta, Arch>,
    visible_modules: &V,
    key: &K,
) -> Option<LoadedCore<D, Arch>>
where
    K: Clone + Ord,
    D: 'static,
    Arch: RelocationArch,
    V: VisibleModules<K, D, Arch>,
{
    context
        .committed
        .key_id(key)
        .and_then(|id| visible_module(context, visible_modules, id))
        .or_else(|| visible_modules.module(key))
        .and_then(|module| module.as_loaded::<D>().cloned())
}

#[inline]
fn visible_module<K, D, Meta, V, Arch>(
    context: &LinkContext<K, D, Meta, Arch>,
    visible_modules: &V,
    id: KeyId,
) -> Option<ModuleHandle<Arch>>
where
    K: Clone + Ord,
    D: 'static,
    Arch: RelocationArch,
    V: VisibleModules<K, D, Arch>,
{
    context.committed.get(id).map(Into::into).or_else(|| {
        let key = context.committed.key(id)?;
        visible_modules.module(key)
    })
}
