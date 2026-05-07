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
    runtime::{AnyRawDynamic, BuiltinArch, BuiltinRelocationHandler},
    session::{GraphEntry, LoadSession},
    storage::CommittedEntry,
};
use crate::{
    LinkerError, Loader, Result,
    entity::SecondaryMap,
    image::{AnyScannedDynamic, LoadedCore, LoadedModule, RawDynamic},
    loader::LoadHook,
    os::{DefaultMmap, Mmap},
    relocation::{RelocationArch, Relocator, SymbolLookup},
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
/// `Linker` stores a heterogeneous dependency graph: every module carries its
/// own `RelocationArch`, while the context and relocation scopes retain them
/// through [`LoadedModule`].
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

impl<'a, K, D, L, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD: 'static, P, O, V>
    Linker<'a, K, D, L, R, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD, P, O, V>
where
    K: Clone + Ord,
    D: 'static,
{
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

    pub fn map_pipeline(
        mut self,
        configure: impl FnOnce(LinkPipeline<'a, K>) -> LinkPipeline<'a, K>,
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
    >
where
    K: Clone + Ord,
    D: 'static,
    M: Mmap,
    H: LoadHook<LoaderArch::Layout>,
    Tls: TlsResolver,
    LoaderArch: RelocationArch,
{
    pub fn map_loader<NewM, NewH, NewD, NewTls, NewArch>(
        self,
        configure: impl FnOnce(
            Loader<M, H, D, Tls, LoaderArch>,
        ) -> Loader<NewM, NewH, NewD, NewTls, NewArch>,
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
        NewH: LoadHook<NewArch::Layout>,
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

#[allow(private_bounds)]
impl<
    'a,
    K,
    D,
    M,
    H,
    Tls,
    LoaderArch,
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
        Loader<M, H, D, Tls, LoaderArch>,
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
    H: LoadHook<crate::elf::Elf32Layout>
        + LoadHook<crate::elf::Elf64Layout>
        + LoadHook<LoaderArch::Layout>,
    Tls: TlsResolver,
    LoaderArch: BuiltinArch,
    PreS: SymbolLookup + Clone,
    PostS: SymbolLookup + Clone,
    LazyPreS: SymbolLookup + Send + Sync + 'static + Clone,
    LazyPostS: SymbolLookup + Send + Sync + 'static + Clone,
    PreH: BuiltinRelocationHandler + Clone,
    PostH: BuiltinRelocationHandler + Clone,
    ScopeD: 'static,
    P: RelocationPlanner<K, D>,
    O: LoadObserver<K, D>,
    V: VisibleModules<K, D>,
{
    /// Loads one module and returns the type-erased loaded module.
    pub fn load<'cfg, Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        key: K,
    ) -> Result<LoadedModule<D>>
    where
        K: 'cfg,
        Meta: Default,
        Resolver: KeyResolver<'cfg, K, D, Meta>,
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

    /// Loads one module and downcasts it to the expected architecture.
    pub fn load_typed<'cfg, Meta, Arch>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        key: K,
    ) -> Result<LoadedCore<D, Arch>>
    where
        K: 'cfg,
        Meta: Default,
        Arch: RelocationArch,
        Resolver: KeyResolver<'cfg, K, D, Meta>,
    {
        let loaded = self.load(context, key)?;
        loaded.downcast::<Arch>().ok_or_else(|| {
            LinkerError::context("loaded module architecture did not match requested type").into()
        })
    }

    #[allow(private_bounds)]
    pub fn load_mapped_root<'cfg, Meta, Arch>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        key: K,
        raw: RawDynamic<D, Arch>,
    ) -> Result<LoadedModule<D>>
    where
        K: 'cfg,
        Meta: Default,
        Arch: BuiltinArch,
        Resolver: KeyResolver<'cfg, K, D, Meta>,
    {
        if let Some(loaded) = visible_loaded(context, &self.visible_modules, &key) {
            return Ok(loaded);
        }

        let raw = Arch::wrap_raw(raw);
        let prepared =
            self.prepare_runtime_load(context, move |_, _, session, _, _, observer| {
                observer.on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
                session.resolve.insert_entry(key.clone(), raw);
                Ok(key)
            })?;
        self.execute_prepared_load(context, prepared)
    }

    /// Discovers, plans, and loads one module through the scan-first path.
    #[allow(private_bounds)]
    pub fn load_scan_first<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta>,
        key: K,
    ) -> Result<LoadedModule<D>>
    where
        K: 'static,
        Meta: Default,
        Resolver: KeyResolver<'static, K, D, Meta>,
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
        context: &LinkContext<K, D, Meta>,
        key: &K,
    ) -> Result<ScanDiscovery<K>>
    where
        K: 'static,
        Resolver: KeyResolver<'static, K, D, Meta>,
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

    fn prepare_planned_load(&mut self, mut plan: LinkPlan<K>) -> Result<PreparedLoad<K, D>> {
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
        plan: &mut LinkPlan<K>,
    ) -> Result<Option<mapped::MappedRuntimeMemory>> {
        materialization::normalize_plan(plan)?;
        let mut mapped_runtime = mapped::MappedRuntimeMemory::map::<M, _>(plan)?;

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
        plan: &mut LinkPlan<K>,
    ) -> Result<()> {
        match plan
            .get(module_id)
            .expect("planned runtime module must exist")
            .module()
            .arch_kind()
        {
            crate::arch::ArchKind::X86_64 => runtime
                .repair_module::<_, crate::arch::x86_64::relocation::X86_64Arch>(module_id, plan),
            crate::arch::ArchKind::AArch64 => runtime
                .repair_module::<_, crate::arch::aarch64::relocation::AArch64Arch>(module_id, plan),
            crate::arch::ArchKind::RiscV64 => runtime
                .repair_module::<_, crate::arch::riscv64::relocation::RiscV64Arch>(module_id, plan),
            crate::arch::ArchKind::RiscV32 => runtime
                .repair_module::<_, crate::arch::riscv32::relocation::RiscV32Arch>(module_id, plan),
            crate::arch::ArchKind::LoongArch64 => {
                runtime.repair_module::<_, crate::arch::loongarch64::relocation::LoongArch64Arch>(
                    module_id, plan,
                )
            }
            crate::arch::ArchKind::X86 => {
                runtime.repair_module::<_, crate::arch::x86::relocation::X86Arch>(module_id, plan)
            }
            crate::arch::ArchKind::Arm => {
                runtime.repair_module::<_, crate::arch::arm::relocation::ArmArch>(module_id, plan)
            }
        }
    }

    fn materialize_planned_raw(
        &mut self,
        plan: &MemoryLayoutPlan,
        mapped_runtime: &mut Option<mapped::MappedRuntimeMemory>,
        module_id: ModuleId,
        scanned: AnyScannedDynamic,
    ) -> Result<AnyRawDynamic<D>> {
        match plan
            .materialization(module_id)
            .unwrap_or(Materialization::WholeDsoRegion)
        {
            Materialization::SectionRegions => {
                self.materialize_arena_raw(mapped_runtime, module_id, scanned)
            }
            Materialization::WholeDsoRegion => {
                let mut raw = self.loader.load_scanned_dynamic_as(scanned)?;
                apply_section_overrides_any(&mut raw, module_id, plan);
                Ok(raw)
            }
        }
    }

    fn materialize_arena_raw(
        &mut self,
        mapped_runtime: &mut Option<mapped::MappedRuntimeMemory>,
        module_id: ModuleId,
        scanned: AnyScannedDynamic,
    ) -> Result<AnyRawDynamic<D>> {
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

        if scanned.arch_kind() == LoaderArch::KIND {
            let scanned = LoaderArch::unwrap_scanned(scanned)
                .expect("scanned module arch kind matched the loader arch");
            let mut raw = mapped::build_arena_raw_dynamic::<D, Tls, LoaderArch>(
                scanned,
                runtime,
                init_fn,
                fini_fn,
                force_static_tls,
            )?;
            self.loader.inner.initialize_dynamic(&mut raw)?;
            return Ok(LoaderArch::wrap_raw(raw));
        }

        materialize_arena_raw_cross::<D, Tls>(scanned, runtime, init_fn, fini_fn, force_static_tls)
    }

    fn prepare_runtime_load<'cfg, Meta, Seed>(
        &mut self,
        context: &LinkContext<K, D, Meta>,
        seed_root: Seed,
    ) -> Result<PreparedLoad<K, D>>
    where
        K: 'cfg,
        Resolver: KeyResolver<'cfg, K, D, Meta>,
        Seed: FnOnce(
            &LinkContext<K, D, Meta>,
            &V,
            &mut LoadSession<K, D>,
            &mut Loader<M, H, D, Tls, LoaderArch>,
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
        context: &mut LinkContext<K, D, Meta>,
        prepared: PreparedLoad<K, D>,
    ) -> Result<LoadedModule<D>>
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
                let (scope, binding) = inputs.into_parts();
                let loaded = raw.relocate(&self.relocator, scope, binding)?;
                session.push_ready(key, loaded, direct_deps);
            }
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }

    fn build_relocation_order(
        root: &K,
        pending: &BTreeMap<K, GraphEntry<K, AnyRawDynamic<D>>>,
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
    ) -> Arc<[LoadedModule<D>]>
    where
        K: Ord,
    {
        session
            .resolve
            .group_order
            .iter()
            .map(|scope_key| {
                if let Some(entry) = session.resolve.entries.get(scope_key) {
                    entry.payload.placeholder_module()
                } else {
                    visible_loaded(context, visible_modules, scope_key)
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

enum ScanDiscovery<K> {
    Existing(K),
    Plan(LinkPlan<K>),
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

fn materialize_arena_raw_cross<D, Tls>(
    scanned: AnyScannedDynamic,
    runtime: mapped::RuntimeModuleMemory,
    init_fn: crate::loader::DynLifecycleHandler,
    fini_fn: crate::loader::DynLifecycleHandler,
    force_static_tls: bool,
) -> Result<AnyRawDynamic<D>>
where
    D: Default + 'static,
    Tls: TlsResolver,
{
    match scanned {
        AnyScannedDynamic::X86_64(scanned) => {
            mapped::build_arena_raw_dynamic::<D, Tls, crate::arch::x86_64::relocation::X86_64Arch>(
                scanned,
                runtime,
                init_fn,
                fini_fn,
                force_static_tls,
            )
            .map(AnyRawDynamic::X86_64)
        }
        AnyScannedDynamic::AArch64(scanned) => mapped::build_arena_raw_dynamic::<
            D,
            Tls,
            crate::arch::aarch64::relocation::AArch64Arch,
        >(
            scanned,
            runtime,
            init_fn,
            fini_fn,
            force_static_tls,
        )
        .map(AnyRawDynamic::AArch64),
        AnyScannedDynamic::RiscV64(scanned) => mapped::build_arena_raw_dynamic::<
            D,
            Tls,
            crate::arch::riscv64::relocation::RiscV64Arch,
        >(
            scanned,
            runtime,
            init_fn,
            fini_fn,
            force_static_tls,
        )
        .map(AnyRawDynamic::RiscV64),
        AnyScannedDynamic::RiscV32(scanned) => mapped::build_arena_raw_dynamic::<
            D,
            Tls,
            crate::arch::riscv32::relocation::RiscV32Arch,
        >(
            scanned,
            runtime,
            init_fn,
            fini_fn,
            force_static_tls,
        )
        .map(AnyRawDynamic::RiscV32),
        AnyScannedDynamic::LoongArch64(scanned) => {
            mapped::build_arena_raw_dynamic::<
                D,
                Tls,
                crate::arch::loongarch64::relocation::LoongArch64Arch,
            >(scanned, runtime, init_fn, fini_fn, force_static_tls)
            .map(AnyRawDynamic::LoongArch64)
        }
        AnyScannedDynamic::X86(scanned) => mapped::build_arena_raw_dynamic::<
            D,
            Tls,
            crate::arch::x86::relocation::X86Arch,
        >(
            scanned, runtime, init_fn, fini_fn, force_static_tls
        )
        .map(AnyRawDynamic::X86),
        AnyScannedDynamic::Arm(scanned) => mapped::build_arena_raw_dynamic::<
            D,
            Tls,
            crate::arch::arm::relocation::ArmArch,
        >(
            scanned, runtime, init_fn, fini_fn, force_static_tls
        )
        .map(AnyRawDynamic::Arm),
    }
}

fn apply_section_overrides_any<D>(
    raw: &mut AnyRawDynamic<D>,
    module_id: ModuleId,
    plan: &MemoryLayoutPlan,
) where
    D: 'static,
{
    match raw {
        AnyRawDynamic::X86_64(raw) => apply_section_overrides(raw, module_id, plan),
        AnyRawDynamic::AArch64(raw) => apply_section_overrides(raw, module_id, plan),
        AnyRawDynamic::RiscV64(raw) => apply_section_overrides(raw, module_id, plan),
        AnyRawDynamic::RiscV32(raw) => apply_section_overrides(raw, module_id, plan),
        AnyRawDynamic::LoongArch64(raw) => apply_section_overrides(raw, module_id, plan),
        AnyRawDynamic::X86(raw) => apply_section_overrides(raw, module_id, plan),
        AnyRawDynamic::Arm(raw) => apply_section_overrides(raw, module_id, plan),
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
) -> Option<LoadedModule<D>>
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
