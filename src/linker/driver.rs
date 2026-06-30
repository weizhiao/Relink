use super::{
    context::LinkContext,
    request::{DefaultRelocationPlanner, RelocationPlanner, RelocationRequest, VisibleModules},
    resolve::{LoadResolveContext, ScanResolveContext},
    resolver::KeyResolver,
    scan::{
        GotPltTarget, LinkPipeline, LinkPlan, MappedRuntimeMemory, Materialization,
        MemoryLayoutPlan, ModuleId as PlanModuleId, build_arena_raw_dynamic,
    },
    session::{LoadSession, ResolveSession},
    storage::{KeyId, ModuleId as CommittedModuleId},
};
use crate::{
    LinkerError, Loader, Result,
    image::{
        LoadedCore, ModuleHandle, ModuleScope, ModuleScopeBuilder, RawDynamic, ScannedDynamic,
    },
    memory::{ImageMemory, RegionAccess, VmOffset},
    observer::{LinkObserver, LoadObserver, RelocationObserver, StagedDynamic},
    os::Mmap,
    relocation::{RelocationArch, RelocationHandler, Relocator},
    tls::TlsResolver,
};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{borrow::Borrow, fmt, marker::PhantomData, mem, ops::Deref};

/// Result of a successful linker load operation.
///
/// `committed` contains the newly committed modules' [`ModuleId`](crate::linker::ModuleId)
/// values in load order.
pub struct LoadResult<
    D: 'static,
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = crate::memory::HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    root_id: Option<CommittedModuleId>,
    root: LoadedCore<D, Arch, R, Tls>,
    committed: Box<[CommittedModuleId]>,
}

impl<D: 'static, Arch, R, Tls> fmt::Debug for LoadResult<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadResult")
            .field("root_id", &self.root_id)
            .field("root", &self.root.name())
            .field("committed", &self.committed)
            .finish()
    }
}

impl<D: 'static, Arch, R, Tls> LoadResult<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(
        root_id: Option<CommittedModuleId>,
        root: LoadedCore<D, Arch, R, Tls>,
        committed: Box<[CommittedModuleId]>,
    ) -> Self {
        Self {
            root_id,
            root,
            committed,
        }
    }

    /// Returns the committed module id for the loaded root, if the root belongs
    /// to this link context.
    #[inline]
    pub fn root_id(&self) -> Option<CommittedModuleId> {
        self.root_id
    }

    /// Returns the loaded root module.
    #[inline]
    pub fn root(&self) -> &LoadedCore<D, Arch, R, Tls> {
        &self.root
    }

    /// Returns module ids committed by this load operation in load order.
    #[inline]
    pub fn committed(&self) -> &[CommittedModuleId] {
        &self.committed
    }

    /// Consumes the result and returns the loaded root module.
    #[inline]
    pub fn into_root(self) -> LoadedCore<D, Arch, R, Tls> {
        self.root
    }
}

impl<D: 'static, Arch, R, Tls> Deref for LoadResult<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    type Target = LoadedCore<D, Arch, R, Tls>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.root
    }
}

/// Configurable front-end for runtime dependency discovery and relocation.
///
/// `Linker` stores one relocation domain: all modules committed through one
/// context use the same [`RelocationArch`].
#[doc(hidden)]
pub struct Stage0;

#[doc(hidden)]
pub struct Stage1;

#[doc(hidden)]
pub trait AdvanceStage {
    type Next;
}

impl AdvanceStage for Stage0 {
    type Next = Stage1;
}

impl AdvanceStage for Stage1 {
    type Next = Stage1;
}

pub struct Linker<
    'a,
    K: Clone + Ord,
    Arch: RelocationArch = crate::arch::NativeArch,
    L = Loader<(), (), (), Arch>,
    R = (),
    PreH = (),
    PostH = (),
    RelocObs = (),
    P = DefaultRelocationPlanner,
    O = (),
    V = (),
    Tls: TlsResolver<Arch> = (),
    Stage = Stage0,
> {
    loader: L,
    resolver: R,
    pipeline: LinkPipeline<'a, K, Arch, Tls>,
    relocator: Relocator<(), PreH, PostH, Arch, RelocObs, Tls>,
    planner: P,
    observer: O,
    visible_modules: V,
    scratch_relocation_order: Vec<KeyId>,
    stage: PhantomData<Stage>,
}

impl<'a, K> Linker<'a, K>
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
            stage: PhantomData,
        }
    }

    /// Switch the linker's relocation domain before a loader is attached.
    ///
    /// This mirrors [`Loader::for_arch`] for the dependency-linking front-end:
    /// all modules committed through the resulting [`LinkContext`] use
    /// `NewArch`.
    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn for_arch<NewArch>(
        self,
    ) -> Linker<
        'a,
        K,
        NewArch,
        Loader<(), (), (), NewArch>,
        (),
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
            stage: PhantomData,
        }
    }
}

impl<'a, K> Default for Linker<'a, K>
where
    K: Clone + Ord,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K, L, R, PreH, PostH, RelocObs, P, O, V, Arch, Tls, Stage>
    Linker<'a, K, Arch, L, R, PreH, PostH, RelocObs, P, O, V, Tls, Stage>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Sets the key resolver used to resolve root keys and dependencies.
    pub fn resolver<NewR>(
        self,
        resolver: NewR,
    ) -> Linker<'a, K, Arch, L, NewR, PreH, PostH, RelocObs, P, O, V, Tls, Stage> {
        Linker {
            loader: self.loader,
            resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner: self.planner,
            observer: self.observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
            stage: self.stage,
        }
    }

    /// Sets the relocation planner used after dependency discovery.
    pub fn planner<NewP>(
        self,
        planner: NewP,
    ) -> Linker<'a, K, Arch, L, R, PreH, PostH, RelocObs, NewP, O, V, Tls, Stage> {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner,
            observer: self.observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
            stage: self.stage,
        }
    }

    /// Sets the observer used for linker-level dependency and staging events.
    pub fn observer<NewO>(
        self,
        observer: NewO,
    ) -> Linker<'a, K, Arch, L, R, PreH, PostH, RelocObs, P, NewO, V, Tls, Stage> {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner: self.planner,
            observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
            stage: self.stage,
        }
    }

    /// Sets additional modules that are visible for reuse or lookup.
    pub fn visible_modules<NewV>(
        self,
        visible_modules: NewV,
    ) -> Linker<'a, K, Arch, L, R, PreH, PostH, RelocObs, P, O, NewV, Tls, Stage> {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner: self.planner,
            observer: self.observer,
            visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
            stage: self.stage,
        }
    }
}

impl<'a, K, L, R, PreH, PostH, RelocObs, P, O, V, Arch, Tls, Stage>
    Linker<'a, K, Arch, L, R, PreH, PostH, RelocObs, P, O, V, Tls, Stage>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Stage: AdvanceStage,
{
    /// Reconfigures the scan-first pipeline.
    pub fn map_pipeline(
        mut self,
        configure: impl FnOnce(LinkPipeline<'a, K, Arch, Tls>) -> LinkPipeline<'a, K, Arch, Tls>,
    ) -> Linker<'a, K, Arch, L, R, PreH, PostH, RelocObs, P, O, V, Tls, Stage::Next> {
        self.pipeline = configure(self.pipeline);
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner: self.planner,
            observer: self.observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
            stage: PhantomData,
        }
    }
}

impl<'a, K, L, R, PreH, PostH, RelocObs, P, O, V, Arch, Tls, Stage>
    Linker<'a, K, Arch, L, R, PreH, PostH, RelocObs, P, O, V, Tls, Stage>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Stage: AdvanceStage,
{
    /// Reconfigures the relocator template used for loaded modules.
    pub fn map_relocator<NewPreH, NewPostH, NewRelocObs>(
        self,
        configure: impl FnOnce(
            Relocator<(), PreH, PostH, Arch, RelocObs, Tls>,
        ) -> Relocator<(), NewPreH, NewPostH, Arch, NewRelocObs, Tls>,
    ) -> Linker<'a, K, Arch, L, R, NewPreH, NewPostH, NewRelocObs, P, O, V, Tls, Stage::Next> {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: configure(self.relocator),
            planner: self.planner,
            observer: self.observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
            stage: PhantomData,
        }
    }
}

impl<'a, K, D, Obs, Tls, Arch, M, R, P, O, V>
    Linker<'a, K, Arch, Loader<Obs, D, Tls, Arch, M>, R, (), (), (), P, O, V, Tls, Stage0>
where
    K: Clone + Ord,
    D: 'static,
    Obs: LoadObserver<D, Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    /// Reconfigures the underlying loader.
    ///
    /// This must run before configuring the relocator or scan-first pipeline,
    /// because changing the loader can also change the TLS resolver type.
    #[allow(clippy::type_complexity)]
    pub fn map_loader<NewObs, NewD, NewTls, NewM>(
        self,
        configure: impl FnOnce(Loader<Obs, D, Tls, Arch, M>) -> Loader<NewObs, NewD, NewTls, Arch, NewM>,
    ) -> Linker<
        'a,
        K,
        Arch,
        Loader<NewObs, NewD, NewTls, Arch, NewM>,
        R,
        (),
        (),
        (),
        P,
        O,
        V,
        NewTls,
        Stage0,
    >
    where
        NewObs: LoadObserver<NewD, Arch>,
        NewD: 'static,
        NewTls: TlsResolver<Arch>,
        NewM: Mmap,
    {
        Linker {
            loader: configure(self.loader),
            resolver: self.resolver,
            pipeline: LinkPipeline::new(),
            relocator: Relocator::new(),
            planner: self.planner,
            observer: self.observer,
            visible_modules: self.visible_modules,
            scratch_relocation_order: self.scratch_relocation_order,
            stage: PhantomData,
        }
    }
}

#[allow(private_bounds)]
impl<'a, K, D, Obs, Tls, Arch, M, Resolver, PreH, PostH, RelocObs, P, O, V, Stage>
    Linker<
        'a,
        K,
        Arch,
        Loader<Obs, D, Tls, Arch, M>,
        Resolver,
        PreH,
        PostH,
        RelocObs,
        P,
        O,
        V,
        Tls,
        Stage,
    >
where
    K: Clone + Ord,
    D: Default + 'static,
    Obs: LoadObserver<D, Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + crate::relocation::RelocationValueProvider + GotPltTarget,
    M: Mmap,
    crate::elf::ElfRelType<Arch>: crate::ByteRepr,
    PreH: RelocationHandler<Arch> + Clone,
    PostH: RelocationHandler<Arch> + Clone,
    RelocObs: RelocationObserver<Arch> + Clone,
    P: RelocationPlanner<K, D, Arch, M::Region, Tls>,
    O: LinkObserver<Arch>,
{
    /// Loads one module into this linker's relocation domain.
    pub fn load<'cfg, Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        Resolver: KeyResolver<'cfg, K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        if let Some(result) = visible_loaded(context, &self.visible_modules, key.borrow()) {
            return Ok(result);
        }

        let prepared = self.prepare_runtime_load::<Meta, Q, _>(
            context,
            |context, visible_modules, session, loader, resolver, observer| {
                let mut resolve_context = LoadResolveContext::new(
                    &mut context.committed,
                    visible_modules,
                    session.resolve_mut(),
                );
                let resolved = resolve_context.resolve_root(&key, resolver, observer)?;
                resolve_context.stage_resolved(resolved, loader, observer)
            },
        )?;
        self.execute_prepared_load::<Meta, Q>(context, prepared)
    }

    /// Loads a pre-mapped root dynamic image and resolves its dependencies.
    pub fn load_mapped_root<'cfg, Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
        raw: RawDynamic<D, Arch, M::Region, Tls>,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        Resolver: KeyResolver<'cfg, K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        if let Some(result) = visible_loaded(context, &self.visible_modules, key.borrow()) {
            return Ok(result);
        }

        let prepared = self.prepare_runtime_load::<Meta, Q, _>(
            context,
            move |context, _, session, _, _, observer| {
                observer.on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
                let id = context.committed.intern_key(key.clone());
                session.insert_pending(id, raw);
                Ok(id)
            },
        )?;
        self.execute_prepared_load::<Meta, Q>(context, prepared)
    }

    /// Discovers, plans, and loads one module through the scan-first path.
    pub fn load_scan_first<Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        Resolver: KeyResolver<'static, K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        if let Some(result) = visible_loaded(context, &self.visible_modules, key.borrow()) {
            return Ok(result);
        }

        let prepared = self.prepare_scan_load::<Meta, Q>(context, &key)?;
        self.execute_prepared_load::<Meta, Q>(context, prepared)
    }

    fn prepare_scan_load<Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: &K,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<'static, K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        let mut session = ResolveSession::new();

        let mut resolve_context =
            ScanResolveContext::new(&mut context.committed, &self.visible_modules, &mut session);
        let resolved = resolve_context.resolve_root(key, &mut self.resolver, &mut self.observer)?;
        let root = resolve_context.stage_resolved(resolved, &mut self.loader)?;
        if !resolve_context.contains_pending(root) {
            return Ok(PreparedLoad::runtime(root, LoadSession::new()));
        }
        resolve_context.resolve_dependency_graph::<_, _, _, Q>(
            root,
            &mut self.loader,
            &mut self.resolver,
            &mut self.observer,
        )?;

        let dynamics = session.take_dynamics();
        let dynamic_ids = dynamics.keys().copied().collect::<BTreeSet<_>>();
        let entries: BTreeMap<_, _> = dynamics
            .into_iter()
            .map(|(id, entry)| {
                let key = context
                    .key(id)
                    .expect("scan entry id must resolve to an interned key")
                    .clone();
                let (module, full_deps) = entry.into_parts();
                let full_deps =
                    full_deps.expect("missing resolved dependencies while building scan plan");
                (id, (key, module, full_deps))
            })
            .collect();
        let mut mapped_runtime = None;
        let planned = if entries.is_empty() {
            None
        } else {
            let plan_root = if dynamic_ids.contains(&root) {
                root
            } else {
                session
                    .group_order
                    .iter()
                    .copied()
                    .find(|id| dynamic_ids.contains(id))
                    .expect("dynamic id set must contain at least one group id")
            };
            let plan_group_order = session
                .group_order
                .iter()
                .copied()
                .filter(|id| dynamic_ids.contains(id))
                .collect::<Vec<_>>();
            let mut plan = LinkPlan::new(plan_root, plan_group_order, entries);
            self.pipeline.run(&mut plan)?;
            mapped_runtime = self.prepare_mapped_runtime(&mut plan)?;
            let (_, _, entries, memory_layout) = plan.into_parts();
            Some((entries, memory_layout))
        };
        let mut session = LoadSession::from_resolve(session);
        if let Some((entries, memory_layout)) = planned {
            for (module_id, entry) in entries {
                let (id, key, module, direct_deps) = entry.into_parts();
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
        }

        Ok(PreparedLoad::planned(root, session, mapped_runtime))
    }

    fn prepare_mapped_runtime(
        &mut self,
        plan: &mut LinkPlan<K, Arch, Tls>,
    ) -> Result<Option<MappedRuntimeMemory<M::Region>>> {
        plan.normalize()?;
        let mut mapped_runtime = MappedRuntimeMemory::map(self.loader.mapper(), plan)?;

        if let Some(runtime) = mapped_runtime.as_mut() {
            let modules = plan
                .modules_with_materialization(Materialization::SectionRegions)
                .collect::<Vec<_>>();
            for &module_id in &modules {
                runtime.build_module(module_id, plan.memory_layout())?;
            }
            runtime.populate(plan)?;
            for module_id in modules {
                runtime.repair_module(module_id, plan)?;
            }
        }

        Ok(mapped_runtime)
    }

    fn materialize_planned_raw(
        &mut self,
        plan: &MemoryLayoutPlan,
        mapped_runtime: &mut Option<MappedRuntimeMemory<M::Region>>,
        module_id: PlanModuleId,
        scanned: ScannedDynamic<Arch>,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        match plan
            .materialization(module_id)
            .unwrap_or(Materialization::WholeDsoRegion)
        {
            Materialization::SectionRegions => {
                self.materialize_arena_raw(mapped_runtime, module_id, scanned)
            }
            Materialization::WholeDsoRegion => {
                let mut raw = self.loader.load_scanned_dynamic(scanned)?;
                apply_section_overrides(&mut raw, module_id, plan)?;
                Ok(raw)
            }
        }
    }

    fn materialize_arena_raw(
        &mut self,
        mapped_runtime: &mut Option<MappedRuntimeMemory<M::Region>>,
        module_id: PlanModuleId,
        scanned: ScannedDynamic<Arch>,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        let runtime = mapped_runtime
            .as_mut()
            .ok_or_else(|| {
                LinkerError::runtime_memory(
                    "section-region planned load is missing mapped runtime memory",
                )
            })?
            .take_module(module_id)?;
        let force_static_tls = self.loader.force_static_tls();

        let mut raw =
            build_arena_raw_dynamic::<D, Tls, Arch, M::Region>(scanned, runtime, force_static_tls)?;
        self.loader.notify_after_dynamic_load(&mut raw)?;
        Ok(raw)
    }

    fn prepare_runtime_load<'cfg, Meta, Q, Seed>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        seed_root: Seed,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<'cfg, K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
        Seed: FnOnce(
            &mut LinkContext<K, D, Meta, Arch, Tls>,
            &V,
            &mut LoadSession<D, Arch, M::Region, Tls>,
            &mut Loader<Obs, D, Tls, Arch, M>,
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
            session.resolve_mut(),
        );
        if resolve_context.contains_pending(root) {
            resolve_context.resolve_dependency_graph::<_, _, _, Q>(
                root,
                &mut self.loader,
                &mut self.resolver,
                &mut self.observer,
            )?;
        }

        Ok(PreparedLoad::runtime(root, session))
    }

    fn execute_prepared_load<Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        prepared: PreparedLoad<D, Arch, M::Region, Tls>,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        let PreparedLoad {
            root,
            mut session,
            mapped_runtime,
        } = prepared;

        if !session.pending_is_empty() {
            self.relocate_pending_modules::<Meta, Q>(root, context, &mut session)?;
        }

        if let Some(mapped_runtime) = mapped_runtime.as_ref() {
            mapped_runtime.protect()?;
        }

        let committed = Self::commit_session(context, &mut session);

        let root_id = context.committed.module_id(root);
        let root = context
            .visible_module(&self.visible_modules, root)
            .and_then(|module| {
                module
                    .downcast_ref::<LoadedCore<D, Arch, M::Region, Tls>>()
                    .cloned()
            })
            .ok_or_else(|| LinkerError::context("load root missing after commit"))?;
        Ok(LoadResult::new(root_id, root, committed))
    }

    fn relocate_pending_modules<Meta, Q>(
        &mut self,
        root: KeyId,
        context: &LinkContext<K, D, Meta, Arch, Tls>,
        session: &mut LoadSession<D, Arch, M::Region, Tls>,
    ) -> Result<()>
    where
        K: Borrow<Q>,
        Q: ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        let mut order = mem::take(&mut self.scratch_relocation_order);
        Self::build_relocation_order(root, session, &mut order);
        let scope = Self::build_group_scope::<Meta, Q>(context, session, &self.visible_modules);

        let result = (|| {
            for id in order.drain(..) {
                let key = context
                    .key(id)
                    .expect("pending module id must resolve to an interned key")
                    .clone();
                let entry = session
                    .take_pending_dynamic(id)
                    .expect("missing pending dynamic module while relocating");
                let (raw, direct_deps) = entry.into_parts();
                let direct_deps =
                    direct_deps.expect("missing resolved dependencies while relocating");
                let req = RelocationRequest::new(&key, raw, &scope);
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

            for (id, entry) in session.take_pending_synthetics() {
                let (module, direct_deps) = entry.into_parts();
                session.push_ready(id, module, direct_deps);
            }
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }

    fn build_relocation_order(
        root: KeyId,
        pending: &LoadSession<D, Arch, M::Region, Tls>,
        order: &mut Vec<KeyId>,
    ) {
        order.clear();
        let dynamic_len = pending.pending_dynamic_len();
        if order.capacity() < dynamic_len {
            order.reserve(dynamic_len - order.capacity());
        }
        let mut visited = BTreeSet::new();
        let mut stack = Vec::with_capacity(pending.pending_len().saturating_mul(2));
        stack.push((root, false));

        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                if pending.is_pending_dynamic(id) {
                    order.push(id);
                }
                continue;
            }

            if !visited.insert(id) {
                continue;
            }

            let Some(direct_deps) = pending.pending_direct_deps(id) else {
                continue;
            };

            stack.push((id, true));
            for dep in direct_deps.iter().rev().copied() {
                stack.push((dep, false));
            }
        }
    }

    fn build_group_scope<Meta, Q>(
        context: &LinkContext<K, D, Meta, Arch, Tls>,
        session: &LoadSession<D, Arch, M::Region, Tls>,
        visible_modules: &V,
    ) -> ModuleScope<Arch, Tls>
    where
        K: Borrow<Q>,
        Q: ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        let modules = session
            .group_order()
            .iter()
            .map(|id| {
                if let Some(raw) = session.pending_dynamic(*id) {
                    let module = unsafe { LoadedCore::from_core(raw.core()) };
                    ModuleHandle::from(module)
                } else if let Some(module) = session.pending_synthetic(*id) {
                    module.clone()
                } else {
                    context
                        .visible_module(visible_modules, *id)
                        .expect("scope key must resolve to a visible or pending module")
                }
            })
            .collect::<Vec<_>>();
        let mut scope = ModuleScopeBuilder::new();
        scope.extend(modules);
        scope.into_scope()
    }

    fn commit_session<Meta>(
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        session: &mut LoadSession<D, Arch, M::Region, Tls>,
    ) -> Box<[CommittedModuleId]>
    where
        Meta: Default,
    {
        let mut ready = session.take_ready_to_commit();
        let mut committed = Vec::with_capacity(ready.len());
        for id in session.group_order().iter().copied() {
            let Some(entry) = ready.remove(&id) else {
                continue;
            };
            let (module, direct_deps) = entry.into_parts();
            let module_id = context
                .committed
                .insert_new(id, module, direct_deps, Meta::default());
            committed.push(module_id);
        }
        assert!(
            ready.is_empty(),
            "ready commit entries must all be present in group_order"
        );
        committed.into_boxed_slice()
    }
}

struct PreparedLoad<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> = ()>
{
    root: KeyId,
    session: LoadSession<D, Arch, R, Tls>,
    mapped_runtime: Option<MappedRuntimeMemory<R>>,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    PreparedLoad<D, Arch, R, Tls>
{
    fn runtime(root: KeyId, session: LoadSession<D, Arch, R, Tls>) -> Self {
        Self {
            root,
            session,
            mapped_runtime: None,
        }
    }

    fn planned(
        root: KeyId,
        session: LoadSession<D, Arch, R, Tls>,
        mapped_runtime: Option<MappedRuntimeMemory<R>>,
    ) -> Self {
        Self {
            root,
            session,
            mapped_runtime,
        }
    }
}

fn apply_section_overrides<D, Arch, R, Tls>(
    raw: &mut RawDynamic<D, Arch, R, Tls>,
    module_id: PlanModuleId,
    plan: &MemoryLayoutPlan,
) -> Result<()>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    let module = plan.module(module_id);
    let core = raw.core_ref();
    let segments = core.segments();

    for section_id in module.alloc_sections().iter().copied() {
        if !plan.section_is_override(section_id) {
            continue;
        }
        let metadata = plan.section(section_id);
        let data = plan
            .data(section_id)
            .ok_or_else(|| LinkerError::section_data("planned override section data is missing"))?;
        if data.len() != metadata.size() {
            return Err(LinkerError::section_data(
                "planned section override size does not match the loaded section",
            )
            .into());
        }
        segments.write_bytes(
            segments.base() + VmOffset::new(metadata.source_address()),
            data.as_ref(),
        )?;
    }
    Ok(())
}

#[inline]
fn visible_loaded<K, D, Meta, V, Arch, R, Q, Tls>(
    context: &LinkContext<K, D, Meta, Arch, Tls>,
    visible_modules: &V,
    key: &Q,
) -> Option<LoadResult<D, Arch, R, Tls>>
where
    K: Clone + Ord + Borrow<Q>,
    Q: Ord + ?Sized,
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    V: VisibleModules<K, Arch, Q, Tls>,
{
    if let Some(key_id) = context.key_id(key) {
        let root_id = context.module_id(key_id);
        if let Some(loaded) = context
            .visible_module(visible_modules, key_id)
            .and_then(|module| {
                module
                    .downcast_ref::<LoadedCore<D, Arch, R, Tls>>()
                    .cloned()
            })
        {
            return Some(LoadResult::new(
                root_id,
                loaded,
                Vec::new().into_boxed_slice(),
            ));
        }
    }

    visible_modules
        .module(key)
        .and_then(|module| {
            module
                .downcast_ref::<LoadedCore<D, Arch, R, Tls>>()
                .cloned()
        })
        .map(|loaded| LoadResult::new(None, loaded, Vec::new().into_boxed_slice()))
}
