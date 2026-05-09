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
    session::{GraphEntry, LoadSession},
    storage::CommittedEntry,
};
use crate::{
    LinkerError, Loader, Result,
    entity::SecondaryMap,
    image::{LoadedCore, RawDynamic, ScannedDynamic},
    loader::LoadHook,
    os::{DefaultMmap, Mmap},
    relocation::{RelocationArch, RelocationHandler, Relocator, SymbolLookup},
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{marker::PhantomData, mem};

/// Configurable front-end for runtime dependency discovery and relocation.
///
/// `Linker` stores one relocation domain: all modules committed through one
/// context use the same [`RelocationArch`].
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
    ScopeD: 'static = (),
    P = DefaultRelocationPlanner,
    O = (),
    V = (),
    LinkArch: RelocationArch = crate::arch::NativeArch,
> {
    loader: L,
    resolver: R,
    pipeline: LinkPipeline<'a, K, LinkArch>,
    relocator: Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, LinkArch>,
    planner: P,
    observer: O,
    visible_modules: V,
    scratch_relocation_order: Vec<K>,
    _marker: PhantomData<fn() -> (D, LinkArch)>,
}

impl<'a, K> Linker<'a, K, ()>
where
    K: Clone + Ord,
{
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

impl<
    'a,
    K,
    D,
    L,
    R,
    PreS,
    PostS,
    LazyPreS,
    LazyPostS,
    PreH,
    PostH,
    ScopeD: 'static,
    P,
    O,
    V,
    LinkArch,
> Linker<'a, K, D, L, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, O, V, LinkArch>
where
    K: Clone + Ord,
    D: 'static,
    LinkArch: RelocationArch,
{
    pub fn resolver<NewR>(
        self,
        resolver: NewR,
    ) -> Linker<
        'a,
        K,
        D,
        L,
        NewR,
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
        LinkArch,
    > {
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

    pub fn map_relocator<
        NewPreS,
        NewPostS,
        NewLazyPreS,
        NewLazyPostS,
        NewPreH,
        NewPostH,
        NewScopeD: 'static,
    >(
        self,
        configure: impl FnOnce(
            Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, LinkArch>,
        ) -> Relocator<
            (),
            NewPreS,
            NewPostS,
            NewLazyPreS,
            NewLazyPostS,
            NewPreH,
            NewPostH,
            NewScopeD,
            LinkArch,
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
        LinkArch,
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

    pub fn planner<NewP>(
        self,
        planner: NewP,
    ) -> Linker<
        'a,
        K,
        D,
        L,
        R,
        PreS,
        PostS,
        LazyPreS,
        LazyPostS,
        PreH,
        PostH,
        ScopeD,
        NewP,
        O,
        V,
        LinkArch,
    > {
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

    pub fn observer<NewO>(
        self,
        observer: NewO,
    ) -> Linker<
        'a,
        K,
        D,
        L,
        R,
        PreS,
        PostS,
        LazyPreS,
        LazyPostS,
        PreH,
        PostH,
        ScopeD,
        P,
        NewO,
        V,
        LinkArch,
    > {
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

    pub fn visible_modules<NewV>(
        self,
        visible_modules: NewV,
    ) -> Linker<
        'a,
        K,
        D,
        L,
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
        NewV,
        LinkArch,
    > {
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

    pub fn map_pipeline(
        mut self,
        configure: impl FnOnce(LinkPipeline<'a, K, LinkArch>) -> LinkPipeline<'a, K, LinkArch>,
    ) -> Self {
        self.pipeline = configure(self.pipeline);
        self
    }
}

impl<
    'a,
    K,
    D,
    M,
    H,
    Tls,
    LoaderArch,
    R,
    PreS,
    PostS,
    LazyPreS,
    LazyPostS,
    PreH,
    PostH,
    ScopeD: 'static,
    P,
    O,
    V,
>
    Linker<
        'a,
        K,
        D,
        Loader<M, H, D, Tls, LoaderArch>,
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
        LoaderArch,
    >
where
    K: Clone + Ord,
    D: 'static,
    M: Mmap,
    H: LoadHook<LoaderArch::Layout>,
    Tls: TlsResolver,
    LoaderArch: RelocationArch,
{
    pub fn map_loader<NewM, NewH, NewD, NewTls>(
        self,
        configure: impl FnOnce(
            Loader<M, H, D, Tls, LoaderArch>,
        ) -> Loader<NewM, NewH, NewD, NewTls, LoaderArch>,
    ) -> Linker<
        'a,
        K,
        NewD,
        Loader<NewM, NewH, NewD, NewTls, LoaderArch>,
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
        LoaderArch,
    >
    where
        NewM: Mmap,
        NewH: LoadHook<LoaderArch::Layout>,
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
    ScopeD: 'static,
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
        Arch,
    >
where
    K: Clone + Ord,
    D: Default + 'static,
    M: Mmap,
    H: LoadHook<Arch::Layout>,
    Tls: TlsResolver,
    Arch: RelocationArch + crate::relocation::RelocationValueProvider + mapped::GotPltTarget,
    crate::elf::ElfRelType<Arch>: crate::ByteRepr,
    PreS: SymbolLookup + Clone,
    PostS: SymbolLookup + Clone,
    LazyPreS: SymbolLookup + Send + Sync + 'static + Clone,
    LazyPostS: SymbolLookup + Send + Sync + 'static + Clone,
    PreH: RelocationHandler<Arch> + Clone,
    PostH: RelocationHandler<Arch> + Clone,
    ScopeD: 'static,
    P: RelocationPlanner<K, D, Arch>,
    O: LoadObserver<K, D, Arch>,
    V: VisibleModules<K, D, Arch>,
{
    /// Loads one module into this linker's relocation domain.
    pub fn load<'cfg, Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        key: K,
    ) -> Result<LoadedCore<D, Arch>>
    where
        K: 'cfg,
        Meta: Default,
        Resolver: KeyResolver<'cfg, K, D, Meta, Arch>,
    {
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
            return Ok(loaded);
        }

        let prepared = self.prepare_runtime_load(
            context,
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

    pub fn load_mapped_root<'cfg, Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        key: K,
        raw: RawDynamic<D, Arch>,
    ) -> Result<LoadedCore<D, Arch>>
    where
        K: 'cfg,
        Meta: Default,
        Resolver: KeyResolver<'cfg, K, D, Meta, Arch>,
    {
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
            return Ok(loaded);
        }

        let prepared =
            self.prepare_runtime_load(context, move |_, _, session, _, _, observer| {
                observer.on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
                session.resolve.insert_entry(key.clone(), raw);
                Ok(key)
            })?;
        self.execute_prepared_load(context, prepared)
    }

    /// Discovers, plans, and loads one module through the scan-first path.
    pub fn load_scan_first<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch>,
        key: K,
    ) -> Result<LoadedCore<D, Arch>>
    where
        K: 'static,
        Meta: Default,
        Resolver: KeyResolver<'static, K, D, Meta, Arch>,
    {
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
            return Ok(loaded);
        }

        let prepared = match self.prepare_scan_load(context, &key)? {
            ScanDiscovery::Existing(root) => PreparedLoad::runtime(root, LoadSession::new()),
            ScanDiscovery::Plan(plan) => self.prepare_planned_load(plan)?,
        };
        self.execute_prepared_load(context, prepared)
    }

    fn prepare_scan_load<Meta>(
        &mut self,
        context: &LinkContext<K, D, Meta, Arch>,
        key: &K,
    ) -> Result<ScanDiscovery<K, Arch>>
    where
        K: 'static,
        Resolver: KeyResolver<'static, K, D, Meta, Arch>,
    {
        let mut session = crate::linker::session::ResolveSession::new();
        let mut resolve_context = ScanResolveContext::new(
            context.committed.view(),
            &self.visible_modules,
            &mut session,
        );
        let root =
            resolve_context.stage_resolved(self.resolver.load_root(key)?, &mut self.loader)?;
        if !resolve_context.contains_pending(&root) {
            return Ok(ScanDiscovery::Existing(root));
        }
        resolve_context.resolve_dependency_graph(
            root.clone(),
            &mut self.loader,
            &mut self.resolver,
        )?;

        let crate::linker::session::ResolveSession {
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
        self.pipeline.run(&mut plan)?;
        Ok(ScanDiscovery::Plan(plan))
    }

    fn prepare_planned_load(
        &mut self,
        mut plan: LinkPlan<K, Arch>,
    ) -> Result<PreparedLoad<K, D, Arch>> {
        let mut mapped_runtime = self.prepare_mapped_runtime(&mut plan)?;

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
            let raw = self.materialize_planned_raw(
                &memory_layout,
                &mut mapped_runtime,
                module_id,
                module,
            )?;
            self.observer
                .on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
            session.insert_resolved_pending(key, raw, direct_deps);
        }

        Ok(PreparedLoad::planned(
            module_keys[root].clone(),
            session,
            mapped_runtime,
        ))
    }

    fn prepare_mapped_runtime(
        &mut self,
        plan: &mut LinkPlan<K, Arch>,
    ) -> Result<Option<mapped::MappedRuntimeMemory>> {
        materialization::normalize_plan(plan)?;
        let mut mapped_runtime = mapped::MappedRuntimeMemory::map::<M, _, Arch>(plan)?;

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
        runtime: &mut mapped::MappedRuntimeMemory,
        module_id: ModuleId,
        plan: &mut LinkPlan<K, Arch>,
    ) -> Result<()> {
        runtime.repair_module::<_, Arch>(module_id, plan)
    }

    fn materialize_planned_raw(
        &mut self,
        plan: &MemoryLayoutPlan,
        mapped_runtime: &mut Option<mapped::MappedRuntimeMemory>,
        module_id: ModuleId,
        scanned: ScannedDynamic<Arch::Layout>,
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
        mapped_runtime: &mut Option<mapped::MappedRuntimeMemory>,
        module_id: ModuleId,
        scanned: ScannedDynamic<Arch::Layout>,
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

        let mut raw = mapped::build_arena_raw_dynamic::<D, Tls, Arch>(
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
        context: &LinkContext<K, D, Meta, Arch>,
        seed_root: Seed,
    ) -> Result<PreparedLoad<K, D, Arch>>
    where
        K: 'cfg,
        Resolver: KeyResolver<'cfg, K, D, Meta, Arch>,
        Seed: FnOnce(
            &LinkContext<K, D, Meta, Arch>,
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
            &self.visible_modules,
            &mut session,
            &mut self.loader,
            &mut self.resolver,
            &mut self.observer,
        )?;
        let mut resolve_context = LoadResolveContext::new(
            context.committed.view(),
            &self.visible_modules,
            &mut session.resolve,
        );
        if resolve_context.contains_pending(&root) {
            resolve_context.resolve_dependency_graph(
                root.clone(),
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
        prepared: PreparedLoad<K, D, Arch>,
    ) -> Result<LoadedCore<D, Arch>>
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

    fn relocate_pending_modules<Meta>(
        &mut self,
        root: &K,
        context: &LinkContext<K, D, Meta, Arch>,
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
                    .with_object(raw)
                    .shared_scope(scope)
                    .binding(binding)
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
        context: &LinkContext<K, D, Meta, Arch>,
        session: &LoadSession<K, D, Arch>,
        visible_modules: &V,
    ) -> Arc<[LoadedCore<D, Arch>]>
    where
        K: Ord,
    {
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
        context: &mut LinkContext<K, D, Meta, Arch>,
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

enum ScanDiscovery<K, Arch: RelocationArch> {
    Existing(K),
    Plan(LinkPlan<K, Arch>),
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
        .get(key)
        .cloned()
        .or_else(|| visible_modules.loaded(key))
}
