use super::{
    context::LinkContext,
    driver::{Linker, LoadResult},
    request::{RelocationPlanner, RelocationRequest, VisibleModules},
    resolve::LoadResolveContext,
    resolver::KeyResolver,
    scan::{GotPltTarget, LinkPipeline, MappedRuntimeMemory},
    session::{GraphEntry, LoadSession},
    storage::KeySlot,
};
use crate::{
    Loader, LoaderRun, Result,
    image::{LoadedCore, RawDynamic},
    lazy::traits::LazyBinder,
    memory::RegionAccess,
    observer::{LoadObserver, RelocationObserver},
    os::Mmap,
    relocation::RelocationArch,
    runtime::CodeExecutor,
    tls::TlsResolver,
};
use alloc::{borrow::ToOwned, vec::Vec};
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
    RelocBinder,
    P,
    V,
    Tls: TlsResolver<Arch>,
    Stage,
    Obs = (),
> {
    pub(super) linker: &'run Linker<'a, K, Arch, L, R, RelocBinder, P, V, Tls, Stage>,
    pub(super) pipeline: LinkPipeline<'a, K, Arch, Tls>,
    pub(super) observer: Obs,
    pub(super) scratch_relocation_order: Vec<KeySlot>,
}

impl<'run, 'a, K, Arch, L, R, RelocBinder, P, V, Tls, Stage, Obs>
    LinkerRun<'run, 'a, K, Arch, L, R, RelocBinder, P, V, Tls, Stage, Obs>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Sets the observer used by this linker run.
    #[inline]
    pub fn with_observer<NewObs>(
        self,
        observer: NewObs,
    ) -> LinkerRun<'run, 'a, K, Arch, L, R, RelocBinder, P, V, Tls, Stage, NewObs>
    where
        NewObs: RelocationObserver<Arch>,
    {
        LinkerRun {
            linker: self.linker,
            pipeline: self.pipeline,
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
            linker,
            pipeline,
            observer,
            scratch_relocation_order,
        } = self;

        Self {
            linker,
            pipeline: configure(pipeline),
            observer,
            scratch_relocation_order,
        }
    }
}

#[allow(private_bounds)]
impl<'run, 'a, K, D, Tls, Arch, M, Exec, Resolver, RelocBinder, P, V, Stage, Obs>
    LinkerRun<
        'run,
        'a,
        K,
        Arch,
        Loader<D, Tls, Arch, M, Exec>,
        Resolver,
        RelocBinder,
        P,
        V,
        Tls,
        Stage,
        Obs,
    >
where
    K: Clone + Ord,
    D: Default + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + crate::relocation::RelocationValueProvider + GotPltTarget,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
    crate::elf::ElfRelType<Arch>: crate::ByteRepr,
    Obs: LoadObserver<D, Arch> + RelocationObserver<Arch>,
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
        if let Some(result) = visible_loaded(context, key.borrow()) {
            return Ok(result);
        }

        let linker = self.linker;
        let mut session = LoadSession::new();
        let mut loader = linker.loader.run().with_observer(&mut self.observer);
        let mut resolve_context = LoadResolveContext::new(
            &mut context.committed,
            &linker.visible_modules,
            session.resolve_mut(),
        );
        let resolved = resolve_context.resolve_root(&key, &linker.resolver)?;
        let root = resolve_context.stage(resolved, &mut loader)?;
        let prepared = Self::prepare_direct_load::<Meta, Q>(
            context,
            &linker.visible_modules,
            &linker.resolver,
            root,
            session,
            &mut loader,
        )?;
        self.finish_load::<Meta>(context, prepared)
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
        if let Some(result) = visible_loaded(context, key.borrow()) {
            return Ok(result);
        }

        let linker = self.linker;
        let mut session = LoadSession::new();
        let root = context.committed.intern_key(key);
        session
            .resolve_mut()
            .dynamics
            .insert(root, GraphEntry::new(raw));
        let mut loader = linker.loader.run().with_observer(&mut self.observer);
        let prepared = Self::prepare_direct_load::<Meta, Q>(
            context,
            &linker.visible_modules,
            &linker.resolver,
            root,
            session,
            &mut loader,
        )?;
        self.finish_load::<Meta>(context, prepared)
    }

    fn prepare_direct_load<'cfg, Meta, Q>(
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        visible_modules: &V,
        resolver: &Resolver,
        root: KeySlot,
        mut session: LoadSession<D, Arch, M::Region, Tls>,
        loader: &mut LoaderRun<'_, &mut Obs, D, Tls, Arch, M, Exec>,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        let mut resolve_context = LoadResolveContext::new(
            &mut context.committed,
            visible_modules,
            session.resolve_mut(),
        );
        if resolve_context.contains_pending(root) {
            resolve_context.resolve_dependency_graph::<_, _, _, Q>(root, loader, resolver)?;
        }

        Ok(PreparedLoad::direct(root, session))
    }

    pub(in crate::linker) fn finish_load<Meta>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        prepared: PreparedLoad<D, Arch, M::Region, Tls>,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        Meta: Default,
    {
        let PreparedLoad {
            root: root_slot,
            mut session,
            mapped_runtime,
        } = prepared;

        if !session.pending_is_empty() {
            self.relocate_pending_modules(root_slot, context, &mut session)?;
        }

        let root = session
            .loaded_root(root_slot)
            .or_else(|| {
                context
                    .committed
                    .get_by_key(root_slot)
                    .and_then(|module| module.downcast_ref::<LoadedCore<D, Arch, M::Region, Tls>>())
                    .cloned()
            })
            .expect("load root must resolve to a loaded core before commit");

        if let Some(mapped_runtime) = mapped_runtime.as_ref() {
            mapped_runtime.protect()?;
        }

        let committed = session.commit_into(&mut context.committed)?;

        let root_id = context
            .committed
            .module_for_key(root_slot)
            .map(|slot| context.committed.make_module_id(slot))
            .expect("committed load root must have a module id");
        Ok(LoadResult::new(root_id, root, committed))
    }

    fn relocate_pending_modules<Meta>(
        &mut self,
        root: KeySlot,
        context: &LinkContext<K, D, Meta, Arch, Tls>,
        session: &mut LoadSession<D, Arch, M::Region, Tls>,
    ) -> Result<()> {
        let mut order = mem::take(&mut self.scratch_relocation_order);
        session.build_relocation_order(root, &mut order);
        let scope = session.build_scope(context);

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
                let inputs = self.linker.planner.plan(&req)?;
                let raw = req.into_raw();
                let (scope, binding) = inputs.into_parts();
                let loaded = self
                    .linker
                    .relocator
                    .run(raw)
                    .shared_scope(scope)
                    .binding(binding)
                    .observer(&mut self.observer)
                    .relocate()?;
                session.push_ready(id, loaded, direct_deps);
            }

            session.mark_module_handles_ready();
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }
}

#[allow(private_bounds)]
impl<'a, K, D, Tls, Arch, M, Exec, Resolver, RelocBinder, P, V, Stage>
    Linker<'a, K, Arch, Loader<D, Tls, Arch, M, Exec>, Resolver, RelocBinder, P, V, Tls, Stage>
where
    K: Clone + Ord,
    D: Default + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + crate::relocation::RelocationValueProvider + GotPltTarget,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
    crate::elf::ElfRelType<Arch>: crate::ByteRepr,
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

pub(in crate::linker) struct PreparedLoad<
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    root: KeySlot,
    session: LoadSession<D, Arch, R, Tls>,
    mapped_runtime: Option<MappedRuntimeMemory<R>>,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    PreparedLoad<D, Arch, R, Tls>
{
    pub(in crate::linker) fn direct(root: KeySlot, session: LoadSession<D, Arch, R, Tls>) -> Self {
        Self {
            root,
            session,
            mapped_runtime: None,
        }
    }

    pub(in crate::linker) fn planned(
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

#[inline]
pub(in crate::linker) fn visible_loaded<K, D, Meta, Arch, R, Q, Tls>(
    context: &LinkContext<K, D, Meta, Arch, Tls>,
    key: &Q,
) -> Option<LoadResult<D, Arch, R, Tls>>
where
    K: Clone + Ord + Borrow<Q>,
    Q: Ord + ?Sized,
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    let key_id = context.key_id(key)?;
    let key_slot = context
        .committed
        .key_slot(key_id)
        .expect("cached key id must belong to this context");
    let root_id = context
        .committed
        .module_for_key(key_slot)
        .map(|slot| context.committed.make_module_id(slot))?;

    context
        .committed
        .get_by_key(key_slot)?
        .downcast_ref::<LoadedCore<D, Arch, R, Tls>>()
        .cloned()
        .map(|loaded| LoadResult::new(root_id, loaded, Vec::new().into_boxed_slice()))
}
