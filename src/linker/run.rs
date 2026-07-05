use super::{
    context::LinkContext,
    driver::{Linker, LoadResult},
    request::{RelocationPlanner, RelocationRequest, VisibleModules},
    resolve::{LoadResolveContext, ScanResolveContext},
    resolver::KeyResolver,
    scan::{
        GotPltTarget, LinkPipeline, LinkPlan, MappedRuntimeMemory, Materialization,
        MemoryLayoutPlan, ModuleId as PlanModuleId, build_arena_raw_dynamic,
    },
    session::{LoadSession, ResolveSession},
    storage::{KeySlot, ModuleId as CommittedModuleId},
};
use crate::{
    LinkerError, Loader, LoaderRun, Result,
    image::{
        LoadedCore, ModuleHandle, ModuleScope, ModuleScopeBuilder, RawDynamic, ScannedDynamic,
    },
    lazy::traits::LazyBinder,
    memory::{ImageMemory, RegionAccess, VmOffset},
    observer::RelocationObserver,
    os::Mmap,
    relocation::{RelocationArch, RelocationHandler, Relocator},
    runtime::CodeExecutor,
    tls::TlsResolver,
};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{borrow::Borrow, mem};

/// Per-run linker state.
///
/// A [`Linker`] owns reusable configuration. `LinkerRun` owns scratch storage
/// used while resolving and relocating one sequence of loads.
pub struct LinkerRun<
    'run,
    'a,
    K: Clone + Ord,
    Arch: RelocationArch,
    L,
    R,
    PreH,
    PostH,
    RelocBinder,
    P,
    V,
    Tls: TlsResolver<Arch>,
    RelocObs = (),
> {
    pub(super) loader: &'run L,
    pub(super) resolver: &'run R,
    pub(super) pipeline: LinkPipeline<'a, K, Arch, Tls>,
    pub(super) relocator: &'run Relocator<PreH, PostH, RelocBinder>,
    pub(super) planner: &'run P,
    pub(super) visible_modules: &'run V,
    pub(super) observer: RelocObs,
    pub(super) scratch_relocation_order: Vec<KeySlot>,
}

impl<'run, 'a, K, Arch, L, R, PreH, PostH, RelocBinder, P, V, Tls, RelocObs>
    LinkerRun<'run, 'a, K, Arch, L, R, PreH, PostH, RelocBinder, P, V, Tls, RelocObs>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Sets the relocation observer used by this linker run.
    #[inline]
    pub fn with_observer<NewRelocObs>(
        self,
        observer: NewRelocObs,
    ) -> LinkerRun<'run, 'a, K, Arch, L, R, PreH, PostH, RelocBinder, P, V, Tls, NewRelocObs>
    where
        NewRelocObs: RelocationObserver<Arch>,
    {
        LinkerRun {
            loader: self.loader,
            resolver: self.resolver,
            pipeline: self.pipeline,
            relocator: self.relocator,
            planner: self.planner,
            visible_modules: self.visible_modules,
            observer,
            scratch_relocation_order: self.scratch_relocation_order,
        }
    }

    /// Reconfigures the scan-first pipeline for this run.
    #[inline]
    pub fn map_pipeline(
        self,
        configure: impl FnOnce(LinkPipeline<'a, K, Arch, Tls>) -> LinkPipeline<'a, K, Arch, Tls>,
    ) -> Self {
        let Self {
            loader,
            resolver,
            pipeline,
            relocator,
            planner,
            visible_modules,
            observer,
            scratch_relocation_order,
        } = self;

        Self {
            loader,
            resolver,
            pipeline: configure(pipeline),
            relocator,
            planner,
            visible_modules,
            observer,
            scratch_relocation_order,
        }
    }
}

#[allow(private_bounds)]
impl<'run, 'a, K, D, Tls, Arch, M, Exec, Resolver, PreH, PostH, RelocBinder, P, V, RelocObs>
    LinkerRun<
        'run,
        'a,
        K,
        Arch,
        Loader<D, Tls, Arch, M, Exec>,
        Resolver,
        PreH,
        PostH,
        RelocBinder,
        P,
        V,
        Tls,
        RelocObs,
    >
where
    K: Clone + Ord,
    D: Default + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + crate::relocation::RelocationValueProvider + GotPltTarget,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
    crate::elf::ElfRelType<Arch>: crate::ByteRepr,
    PreH: RelocationHandler<Arch> + Clone,
    PostH: RelocationHandler<Arch> + Clone,
    RelocObs: RelocationObserver<Arch>,
    RelocBinder: LazyBinder<Arch> + Clone,
    P: RelocationPlanner<K, D, Arch, M::Region, Tls>,
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
        Resolver: KeyResolver<K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        if let Some(result) = visible_loaded(context, self.visible_modules, key.borrow()) {
            return Ok(result);
        }

        let prepared = self.prepare_direct_load::<Meta, Q, _>(
            context,
            |context, visible_modules, session, loader, resolver| {
                let mut resolve_context = LoadResolveContext::new(
                    &mut context.committed,
                    visible_modules,
                    session.resolve_mut(),
                );
                let resolved = resolve_context.resolve_root(&key, resolver)?;
                resolve_context.stage_resolved(resolved, loader)
            },
        )?;
        self.finish_prepared_load::<Meta, Q>(context, prepared)
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
        Resolver: KeyResolver<K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        if let Some(result) = visible_loaded(context, self.visible_modules, key.borrow()) {
            return Ok(result);
        }

        let prepared =
            self.prepare_direct_load::<Meta, Q, _>(context, move |context, _, session, _, _| {
                let slot = context.committed.intern_key(key.clone());
                session.insert_pending(slot, raw);
                Ok(slot)
            })?;
        self.finish_prepared_load::<Meta, Q>(context, prepared)
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
        Resolver: KeyResolver<K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        if let Some(result) = visible_loaded(context, self.visible_modules, key.borrow()) {
            return Ok(result);
        }

        let prepared = self.prepare_scan_load::<Meta, Q>(context, &key)?;
        self.finish_prepared_load::<Meta, Q>(context, prepared)
    }

    fn prepare_scan_load<Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: &K,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        let mut session = ResolveSession::new();

        let mut loader = self.loader.run();
        let mut resolve_context =
            ScanResolveContext::new(&mut context.committed, self.visible_modules, &mut session);
        let resolved = resolve_context.resolve_root(key, self.resolver)?;
        let root = resolve_context.stage_resolved(resolved, &mut loader)?;
        if !resolve_context.contains_pending(root) {
            return Ok(PreparedLoad::runtime(root, LoadSession::new()));
        }
        resolve_context.resolve_dependency_graph::<_, _, _, Q>(root, &mut loader, self.resolver)?;

        let dynamics = session.take_dynamics();
        let dynamic_ids = dynamics.keys().copied().collect::<BTreeSet<_>>();
        let entries: BTreeMap<_, _> = dynamics
            .into_iter()
            .map(|(id, entry)| {
                let key = context.committed.key(id).clone();
                let (module, full_deps) = entry.into_parts();
                let full_deps =
                    full_deps.expect("missing resolved dependencies while building scan plan");
                Ok((id, (key, module, full_deps)))
            })
            .collect::<Result<_>>()?;
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
                let (id, _key, module, direct_deps) = entry.into_parts();
                let raw = self.materialize_planned_raw(
                    &memory_layout,
                    &mut mapped_runtime,
                    module_id,
                    module,
                )?;
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

        let raw =
            build_arena_raw_dynamic::<D, Tls, Arch, M::Region>(scanned, runtime, force_static_tls)?;
        Ok(raw)
    }

    fn prepare_direct_load<'cfg, Meta, Q, Seed>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        seed_root: Seed,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
        Seed: FnOnce(
            &mut LinkContext<K, D, Meta, Arch, Tls>,
            &V,
            &mut LoadSession<D, Arch, M::Region, Tls>,
            &mut LoaderRun<'_, (), D, Tls, Arch, M, Exec>,
            &Resolver,
        ) -> Result<KeySlot>,
    {
        let mut session = LoadSession::new();
        let mut loader = self.loader.run();
        let root = seed_root(
            context,
            self.visible_modules,
            &mut session,
            &mut loader,
            self.resolver,
        )?;
        let mut resolve_context = LoadResolveContext::new(
            &mut context.committed,
            self.visible_modules,
            session.resolve_mut(),
        );
        if resolve_context.contains_pending(root) {
            resolve_context.resolve_dependency_graph::<_, _, _, Q>(
                root,
                &mut loader,
                self.resolver,
            )?;
        }

        Ok(PreparedLoad::runtime(root, session))
    }

    fn finish_prepared_load<Meta, Q>(
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

        let root_id = context
            .committed
            .module_for_key(root)
            .map(|slot| context.committed.make_module_id(slot));
        let root = visible_module(context, self.visible_modules, root)
            .and_then(|module| {
                module
                    .downcast_ref::<LoadedCore<D, Arch, M::Region, Tls>>()
                    .cloned()
            })
            .ok_or(LinkerError::LoadRootMissingAfterCommit)?;
        Ok(LoadResult::new(root_id, root, committed))
    }

    fn relocate_pending_modules<Meta, Q>(
        &mut self,
        root: KeySlot,
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
        let scope = Self::build_group_scope::<Meta, Q>(context, session, self.visible_modules);

        let result = (|| {
            for id in order.drain(..) {
                let key = context.committed.key(id).clone();
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
                    .run(raw)
                    .shared_scope(scope)
                    .binding(binding)
                    .observer(&mut self.observer)
                    .relocate()?;
                session.push_ready(id, loaded, direct_deps);
            }

            for (id, entry) in session.take_pending_module_handles() {
                let (module, direct_deps) = entry.into_parts();
                session.push_ready(id, module, direct_deps);
            }
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }

    fn build_relocation_order(
        root: KeySlot,
        pending: &LoadSession<D, Arch, M::Region, Tls>,
        order: &mut Vec<KeySlot>,
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
                } else if let Some(module) = session.pending_module_handle(*id) {
                    module.clone()
                } else {
                    visible_module(context, visible_modules, *id)
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
            debug_assert!(
                context.committed.module_for_key(id).is_none(),
                "loader commit should not replace an already committed module"
            );
            let module_id = context
                .committed
                .insert(id, module, direct_deps, Meta::default());
            committed.push(module_id);
        }
        assert!(
            ready.is_empty(),
            "ready commit entries must all be present in group_order"
        );
        committed.into_boxed_slice()
    }
}

#[allow(private_bounds)]
impl<'a, K, D, Tls, Arch, M, Exec, Resolver, PreH, PostH, RelocBinder, P, V, Stage>
    Linker<
        'a,
        K,
        Arch,
        Loader<D, Tls, Arch, M, Exec>,
        Resolver,
        PreH,
        PostH,
        RelocBinder,
        P,
        V,
        Tls,
        Stage,
    >
where
    K: Clone + Ord,
    D: Default + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + crate::relocation::RelocationValueProvider + GotPltTarget,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
    crate::elf::ElfRelType<Arch>: crate::ByteRepr,
    PreH: RelocationHandler<Arch> + Clone,
    PostH: RelocationHandler<Arch> + Clone,
    RelocBinder: LazyBinder<Arch> + Clone,
    P: RelocationPlanner<K, D, Arch, M::Region, Tls>,
{
    /// Loads one module into this linker's relocation domain.
    pub fn load<'cfg, Meta, Q>(
        &self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        self.run().load::<Meta, Q>(context, key)
    }

    /// Loads a pre-mapped root dynamic image and resolves its dependencies.
    pub fn load_mapped_root<'cfg, Meta, Q>(
        &self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
        raw: RawDynamic<D, Arch, M::Region, Tls>,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        self.run().load_mapped_root::<Meta, Q>(context, key, raw)
    }

    /// Discovers, plans, and loads one module through the scan-first path.
    pub fn load_scan_first<Meta, Q>(
        &self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        self.run().load_scan_first::<Meta, Q>(context, key)
    }
}

struct PreparedLoad<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> = ()>
{
    root: KeySlot,
    session: LoadSession<D, Arch, R, Tls>,
    mapped_runtime: Option<MappedRuntimeMemory<R>>,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    PreparedLoad<D, Arch, R, Tls>
{
    fn runtime(root: KeySlot, session: LoadSession<D, Arch, R, Tls>) -> Self {
        Self {
            root,
            session,
            mapped_runtime: None,
        }
    }

    fn planned(
        root: KeySlot,
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
    let (root_id, module) = if let Some(key_id) = context.key_id(key) {
        let key_slot = context
            .committed
            .key_slot(key_id)
            .expect("cached key id must belong to this context");
        let root_id = context
            .committed
            .module_for_key(key_slot)
            .map(|slot| context.committed.make_module_id(slot));
        (root_id, visible_module(context, visible_modules, key_slot))
    } else {
        (None, None)
    };

    let module = module.or_else(|| visible_modules.module(key))?;
    module
        .downcast_ref::<LoadedCore<D, Arch, R, Tls>>()
        .cloned()
        .map(|loaded| LoadResult::new(root_id, loaded, Vec::new().into_boxed_slice()))
}

#[inline]
fn visible_module<K, D, Meta, V, Arch, Q, Tls>(
    context: &LinkContext<K, D, Meta, Arch, Tls>,
    visible_modules: &V,
    slot: KeySlot,
) -> Option<ModuleHandle<Arch, Tls>>
where
    K: Clone + Ord + Borrow<Q>,
    Q: ?Sized,
    D: 'static,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    V: VisibleModules<K, Arch, Q, Tls>,
{
    if let Some(module) = context.committed.get_by_key(slot).cloned() {
        return Some(module);
    }
    let key = context.committed.key(slot);
    visible_modules.module(key.borrow())
}
