use super::{
    context::LinkContext,
    driver::{Linker, LoadResult},
    resolve::LoadResolveContext,
    resolver::{KeyResolver, SearchOwner},
    scan::{GotPltTarget, LinkPipeline, MappedRuntimeMemory},
    session::{GraphEntry, LoadSession},
    storage::{ContextId, KeySlot, ModuleId},
};
use crate::{
    ByteRepr, Error, LinkContextError, LinkerError, Loader, LoaderRun, Result,
    arch::NativeArch,
    elf::ElfRelType,
    image::{LoadedCore, Module, ModuleScope, RawDynamic},
    lazy::LazyBinder,
    memory::{HostRegion, RegionAccess},
    observer::{
        LinkerInitEvent, LinkerObserver, LinkerRelocationEvent, LoadObserver, RelocationObserver,
    },
    os::Mmap,
    relocation::{RelocationArch, RelocationValueProvider, SymbolRegistry},
    runtime::CodeExecutor,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use core::{borrow::Borrow, fmt, marker::PhantomData, mem, ops::Deref};

/// Per-run linker state.
///
/// A [`Linker`] owns reusable configuration. `LinkerRun` owns scratch storage
/// used while resolving and relocating one sequence of loads.
pub struct LinkerRun<
    'run,
    'pipe,
    K: Clone + Ord,
    Arch: RelocationArch,
    L,
    R,
    RelocBinder,
    Tls: TlsResolver<Arch>,
    Obs = (),
> {
    pub(super) linker: &'run Linker<K, Arch, L, R, RelocBinder, Tls>,
    pub(super) pipeline: LinkPipeline<'pipe, K, Arch, Tls>,
    pub(super) observer: Obs,
    pub(super) scratch_relocation_order: Vec<KeySlot>,
}

impl<'run, 'pipe, K, Arch, L, R, RelocBinder, Tls, Obs>
    LinkerRun<'run, 'pipe, K, Arch, L, R, RelocBinder, Tls, Obs>
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
    ) -> LinkerRun<'run, 'pipe, K, Arch, L, R, RelocBinder, Tls, NewObs>
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
        configure: impl FnOnce(LinkPipeline<'pipe, K, Arch, Tls>) -> LinkPipeline<'pipe, K, Arch, Tls>,
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
impl<'run, 'pipe, K, D, Tls, Arch, M, Exec, Resolver, RelocBinder, Obs>
    LinkerRun<'run, 'pipe, K, Arch, Loader<D, Tls, Arch, M, Exec>, Resolver, RelocBinder, Tls, Obs>
where
    K: Clone + Ord,
    D: Default + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
    ElfRelType<Arch>: ByteRepr,
    Obs: LinkerObserver<K, D, Arch, M::Region, Tls>
        + LoadObserver<D, Arch>
        + RelocationObserver<Arch>,
    RelocBinder: LazyBinder<Arch> + Clone,
{
    /// Loads, commits, and initializes one module and its dependency group.
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
    {
        self.load_with_owner::<Meta, Q>(context, key, None)
    }

    /// Loads one root using search metadata from the module that requested it.
    pub fn load_from<'cfg, Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
        owner: SearchOwner<'_>,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        self.load_with_owner::<Meta, Q>(context, key, Some(owner))
    }

    fn load_with_owner<'cfg, Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
        owner: Option<SearchOwner<'_>>,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        let prepared = self.prepare_load_with_owner::<Meta, Q>(context, key, owner)?;
        let relocated = self.relocate(prepared)?;
        let published = relocated.publish(context)?;
        match published.initialize() {
            Ok(result) => Ok(result),
            Err(failed) => Err(failed.rollback(context)),
        }
    }

    /// Resolves and maps one module group without executing target code.
    pub fn prepare_load<'cfg, Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
    ) -> Result<PreparedLoad<K, D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        self.prepare_load_with_owner::<Meta, Q>(context, key, None)
    }

    /// Resolves and maps one caller-relative root without executing target code.
    pub fn prepare_load_from<'cfg, Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
        owner: SearchOwner<'_>,
    ) -> Result<PreparedLoad<K, D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        self.prepare_load_with_owner::<Meta, Q>(context, key, Some(owner))
    }

    fn prepare_load_with_owner<'cfg, Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
        owner: Option<SearchOwner<'_>>,
    ) -> Result<PreparedLoad<K, D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        context
            .committed
            .ensure_domain(self.linker.loader.domain_id())?;
        if let Some(prepared) = PreparedLoad::visible(context, key.borrow())? {
            return Ok(prepared);
        }

        let linker = self.linker;
        let mut session = LoadSession::new();
        let mut loader = linker.loader.run().with_observer(&mut self.observer);
        let mut resolve_context =
            LoadResolveContext::new(&mut context.committed, session.resolve_mut());
        let resolved = resolve_context.resolve_root::<_, M::Region, _>(
            &key,
            owner,
            &linker.resolver,
            &loader.observer,
        )?;
        let root = resolve_context.stage(resolved, &mut loader)?;
        Self::prepare_direct_load::<Meta, Q>(context, &linker.resolver, root, session, &mut loader)
    }

    /// Loads, commits, and initializes a pre-mapped root dynamic image.
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
    {
        let prepared = self.prepare_mapped_root::<Meta, Q>(context, key, raw)?;
        let relocated = self.relocate(prepared)?;
        let published = relocated.publish(context)?;
        match published.initialize() {
            Ok(result) => Ok(result),
            Err(failed) => Err(failed.rollback(context)),
        }
    }

    /// Resolves dependencies for a pre-mapped root without relocating it.
    pub fn prepare_mapped_root<'cfg, Meta, Q>(
        &mut self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
        raw: RawDynamic<D, Arch, M::Region, Tls>,
    ) -> Result<PreparedLoad<K, D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        context
            .committed
            .ensure_domain(self.linker.loader.domain_id())?;
        context
            .committed
            .ensure_domain(raw.core_ref().domain_id())?;
        if let Some(prepared) = PreparedLoad::visible(context, key.borrow())? {
            return Ok(prepared);
        }

        let linker = self.linker;
        let mut session = LoadSession::new();
        let root = context.committed.intern_key(key);
        session
            .resolve_mut()
            .dynamics
            .insert(root, GraphEntry::new(raw));
        let mut loader = linker.loader.run().with_observer(&mut self.observer);
        Self::prepare_direct_load::<Meta, Q>(context, &linker.resolver, root, session, &mut loader)
    }

    fn prepare_direct_load<'cfg, Meta, Q>(
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        resolver: &Resolver,
        root: KeySlot,
        mut session: LoadSession<D, Arch, M::Region, Tls>,
        loader: &mut LoaderRun<'_, &mut Obs, D, Tls, Arch, M, Exec>,
    ) -> Result<PreparedLoad<K, D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        let mut resolve_context =
            LoadResolveContext::new(&mut context.committed, session.resolve_mut());
        if resolve_context.contains_pending(root) {
            resolve_context.resolve_dependency_graph::<_, _, _, Q>(root, loader, resolver)?;
        }

        PreparedLoad::new(root, session, None, context)
    }

    /// Relocates a prepared module group without borrowing its link context.
    pub fn relocate(
        &mut self,
        prepared: PreparedLoad<K, D, Arch, M::Region, Tls>,
    ) -> Result<RelocatedLoad<K, D, Arch, M::Region, Tls>> {
        let PreparedLoad {
            context,
            root: root_slot,
            existing_root,
            mut session,
            scope,
            symbols,
            root_key,
            mapped_runtime,
        } = prepared;

        if !session.pending_is_empty() {
            self.relocate_pending_modules(root_slot, &scope, &symbols, &mut session)?;
        }

        let root = session
            .loaded_root(root_slot)
            .or(existing_root)
            .expect("load root must resolve to a loaded core before commit");

        if let Some(mapped_runtime) = mapped_runtime.as_ref() {
            mapped_runtime.protect()?;
        }

        let mut init_order = session.init_order();
        self.observer
            .on_init(&mut LinkerInitEvent::new(&root_key, &root, &mut init_order))?;

        Ok(RelocatedLoad {
            context,
            root: root_slot,
            root_module: root,
            session,
            init_order: init_order.into_boxed_slice(),
            marker: PhantomData,
        })
    }

    fn relocate_pending_modules(
        &mut self,
        root: KeySlot,
        scope: &ModuleScope<Arch, Tls>,
        symbols: &Arc<SymbolRegistry<Arch, Tls>>,
        session: &mut LoadSession<D, Arch, M::Region, Tls>,
    ) -> Result<()> {
        let mut order = mem::take(&mut self.scratch_relocation_order);
        session.build_relocation_order(root, &mut order);

        let result = (|| {
            for id in order.drain(..) {
                let entry = session
                    .take_pending_dynamic(id)
                    .expect("missing pending dynamic module while relocating");
                let (raw, direct_deps) = entry.into_parts();
                let direct_deps =
                    direct_deps.expect("missing resolved dependencies while relocating");
                let mut event = LinkerRelocationEvent::new(raw, scope);
                self.observer.on_relocation(&mut event)?;
                let (raw, scope, binding) = event.into_parts();
                let loaded = self
                    .linker
                    .relocator
                    .run(raw)
                    .shared_scope(scope)
                    .symbol_registry(Arc::clone(symbols))
                    .binding(binding)
                    .observer(&mut self.observer)
                    .relocate()?;
                session.push_relocated(id, loaded, direct_deps);
            }

            session.mark_module_handles_ready();
            Ok(())
        })();

        self.scratch_relocation_order = order;
        result
    }
}

#[allow(private_bounds)]
impl<K, D, Tls, Arch, M, Exec, Resolver, RelocBinder>
    Linker<K, Arch, Loader<D, Tls, Arch, M, Exec>, Resolver, RelocBinder, Tls>
where
    K: Clone + Ord,
    D: Default + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
    ElfRelType<Arch>: ByteRepr,
    RelocBinder: LazyBinder<Arch> + Clone,
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
    {
        self.run().load::<Meta, Q>(context, key)
    }

    /// Loads one root using search metadata from the module that requested it.
    pub fn load_from<'cfg, Meta, Q>(
        &self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
        key: K,
        owner: SearchOwner<'_>,
    ) -> Result<LoadResult<D, Arch, M::Region, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Meta: Default,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        self.run().load_from::<Meta, Q>(context, key, owner)
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
    {
        self.run().load_scan_first::<Meta, Q>(context, key)
    }
}

/// A resolved and mapped load transaction that has not executed relocation.
#[must_use = "a prepared load must be relocated or dropped"]
pub struct PreparedLoad<
    K,
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    context: ContextId,
    root: KeySlot,
    existing_root: Option<LoadedCore<D, Arch, R, Tls>>,
    session: LoadSession<D, Arch, R, Tls>,
    scope: ModuleScope<Arch, Tls>,
    symbols: Arc<SymbolRegistry<Arch, Tls>>,
    root_key: K,
    mapped_runtime: Option<MappedRuntimeMemory<R>>,
}

impl<K, D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    PreparedLoad<K, D, Arch, R, Tls>
where
    K: Clone + Ord,
{
    fn visible<Meta, Q>(
        context: &LinkContext<K, D, Meta, Arch, Tls>,
        key: &Q,
    ) -> Result<Option<Self>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let Some((root, _)): Option<(KeySlot, LoadedCore<D, Arch, R, Tls>)> =
            visible_root(context, key)
        else {
            return Ok(None);
        };
        Self::new(root, LoadSession::new(), None, context).map(Some)
    }

    pub(in crate::linker) fn new<Meta>(
        root: KeySlot,
        session: LoadSession<D, Arch, R, Tls>,
        mapped_runtime: Option<MappedRuntimeMemory<R>>,
        context: &LinkContext<K, D, Meta, Arch, Tls>,
    ) -> Result<Self> {
        let existing_root = context
            .committed
            .get_by_key(root)
            .and_then(|module| module.downcast_ref::<LoadedCore<D, Arch, R, Tls>>())
            .cloned();
        let scope = session.build_scope(context)?;
        let root_key = context.committed.key(root).clone();
        Ok(Self {
            context: context.context_id(),
            root,
            existing_root,
            session,
            scope,
            symbols: Arc::clone(&context.symbols),
            root_key,
            mapped_runtime,
        })
    }
}

/// A relocated load transaction ready to publish into its original context.
#[must_use = "a relocated load must be published or dropped"]
pub struct RelocatedLoad<
    K,
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    context: ContextId,
    root: KeySlot,
    root_module: LoadedCore<D, Arch, R, Tls>,
    session: LoadSession<D, Arch, R, Tls>,
    init_order: Box<[LoadedCore<D, Arch, R, Tls>]>,
    marker: PhantomData<fn() -> K>,
}

impl<K, D: 'static, Arch, R, Tls> RelocatedLoad<K, D, Arch, R, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    /// Publishes this relocated module group into its original context.
    ///
    /// Published modules are visible to recursive loads but remain
    /// transactional until their initializers complete.
    pub fn publish<Meta>(
        self,
        context: &mut LinkContext<K, D, Meta, Arch, Tls>,
    ) -> Result<PublishedLoad<D, Arch, R, Tls>>
    where
        Meta: Default,
    {
        if context.context_id() != self.context {
            return Err(LinkerError::context(LinkContextError::ContextMismatch {
                expected: self.context,
                actual: context.context_id(),
            })
            .into());
        }

        let published = self.session.commit_into(&mut context.committed)?;
        let root_id = context
            .committed
            .module_for_key(self.root)
            .map(|slot| context.committed.make_module_id(slot))
            .expect("published load root must have a module id");
        Ok(PublishedLoad::new(
            root_id,
            self.root_module,
            published.ids,
            self.init_order,
        ))
    }
}

/// A published module group whose initializers have not completed yet.
#[must_use = "a published load must be initialized or rolled back"]
pub struct PublishedLoad<
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    root_id: ModuleId,
    root: LoadedCore<D, Arch, R, Tls>,
    modules: Box<[ModuleId]>,
    init_order: Box<[LoadedCore<D, Arch, R, Tls>]>,
}

impl<D: 'static, Arch, R, Tls> fmt::Debug for PublishedLoad<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedLoad")
            .field("root_id", &self.root_id)
            .field("root", &self.root.name())
            .field("modules", &self.modules)
            .field("pending_initializers", &self.init_order.len())
            .finish()
    }
}

impl<D: 'static, Arch, R, Tls> PublishedLoad<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn new(
        root_id: ModuleId,
        root: LoadedCore<D, Arch, R, Tls>,
        modules: Box<[ModuleId]>,
        init_order: Box<[LoadedCore<D, Arch, R, Tls>]>,
    ) -> Self {
        Self {
            root_id,
            root,
            modules,
            init_order,
        }
    }

    /// Returns the published module id for the loaded root.
    #[inline]
    pub fn root_id(&self) -> ModuleId {
        self.root_id
    }

    /// Returns the loaded root module.
    #[inline]
    pub fn root(&self) -> &LoadedCore<D, Arch, R, Tls> {
        &self.root
    }

    /// Returns module ids published by this load operation in load order.
    #[inline]
    pub fn modules(&self) -> &[ModuleId] {
        &self.modules
    }

    /// Executes module initializers in dependency order.
    pub fn initialize(
        self,
    ) -> core::result::Result<LoadResult<D, Arch, R, Tls>, FailedLoad<D, Arch, R, Tls>> {
        let result = self.init_order.iter().try_for_each(Module::initialize);
        if let Err(error) = result {
            return Err(FailedLoad { error, load: self });
        }
        Ok(LoadResult::new(self.root_id, self.root, self.modules))
    }

    /// Removes this published module group from its link context.
    pub fn rollback<K, Meta>(self, context: &mut LinkContext<K, D, Meta, Arch, Tls>) -> Result<()>
    where
        K: Clone + Ord,
    {
        let expected = self.root_id.context();
        if context.context_id() != expected {
            return Err(LinkerError::context(LinkContextError::ContextMismatch {
                expected,
                actual: context.context_id(),
            })
            .into());
        }
        for id in self.modules.into_vec().into_iter().rev() {
            context
                .remove(id)
                .expect("published load must remain removable from its publish context");
        }
        Ok(())
    }
}

impl<D: 'static, Arch, R, Tls> Deref for PublishedLoad<D, Arch, R, Tls>
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

/// A published load whose initialization failed and can be rolled back.
#[must_use = "a failed load must be rolled back"]
pub struct FailedLoad<
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    error: Error,
    load: PublishedLoad<D, Arch, R, Tls>,
}

impl<D: 'static, Arch, R, Tls> fmt::Debug for FailedLoad<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FailedLoad")
            .field("error", &self.error)
            .field("root_id", &self.load.root_id)
            .field("modules", &self.load.modules)
            .finish()
    }
}

impl<D: 'static, Arch, R, Tls> FailedLoad<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    /// Returns the initialization error.
    #[inline]
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Returns module ids published by the failed load in load order.
    #[inline]
    pub fn modules(&self) -> &[ModuleId] {
        &self.load.modules
    }

    /// Removes the published modules from their link context and returns the
    /// initialization error.
    pub fn rollback<K, Meta>(self, context: &mut LinkContext<K, D, Meta, Arch, Tls>) -> Error
    where
        K: Clone + Ord,
    {
        match self.load.rollback(context) {
            Ok(()) => self.error,
            Err(error) => error,
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
    let (key_slot, loaded) = visible_root(context, key)?;
    let root_id = context
        .committed
        .module_for_key(key_slot)
        .map(|slot| context.committed.make_module_id(slot))?;

    Some(LoadResult::new(
        root_id,
        loaded,
        Vec::new().into_boxed_slice(),
    ))
}

#[inline]
fn visible_root<K, D, Meta, Arch, R, Q, Tls>(
    context: &LinkContext<K, D, Meta, Arch, Tls>,
    key: &Q,
) -> Option<(KeySlot, LoadedCore<D, Arch, R, Tls>)>
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
    let loaded = context
        .committed
        .get_by_key(key_slot)?
        .downcast_ref::<LoadedCore<D, Arch, R, Tls>>()?
        .clone();
    Some((key_slot, loaded))
}
