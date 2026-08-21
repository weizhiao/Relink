use super::{
    context::LinkContext,
    driver::{Linker, LoadResult},
    resolve::LoadResolveContext,
    resolver::KeyResolver,
    scan::{GotPltTarget, LinkPipeline, MappedRuntimeMemory},
    session::{LoadSession, ResolveSession},
    storage::{ContextId, ModuleId, ModuleKey, ModuleLease, ModuleSlot},
};
use crate::{
    ByteRepr, Error, LinkContextError, LinkerError, Loader, Result,
    arch::NativeArch,
    elf::ElfRelType,
    image::{
        GlobalScope, LookupScope, Module, ModuleHandle, ModuleScope, ModuleSearch, RawDynamic,
    },
    lazy::LazyBinder,
    memory::RegionAccess,
    observer::{LinkerObserver, LinkerRelocationEvent, LoadObserver, RelocationObserver},
    os::Mmap,
    relocation::{RelocationArch, RelocationValueProvider, SymbolRegistry},
    runtime::CodeExecutor,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt, mem};

/// Per-run linker state.
///
/// A [`Linker`] owns reusable configuration. `LinkerRun` owns scratch storage
/// used while resolving and relocating one sequence of loads.
pub struct LinkerRun<
    'run,
    'pipe,
    Arch: RelocationArch,
    L,
    R,
    RelocBinder,
    Tls: TlsResolver<Arch>,
    Obs = (),
> {
    pub(super) linker: &'run Linker<Arch, L, R, RelocBinder, Tls>,
    pub(super) pipeline: LinkPipeline<'pipe, Arch, Tls>,
    pub(super) observer: Obs,
    pub(super) scratch_order: Vec<ModuleSlot>,
}

impl<'run, 'pipe, Arch, L, R, RelocBinder, Tls, Obs>
    LinkerRun<'run, 'pipe, Arch, L, R, RelocBinder, Tls, Obs>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Sets the observer used by this linker run.
    #[inline]
    pub fn with_observer<NewObs>(
        self,
        observer: NewObs,
    ) -> LinkerRun<'run, 'pipe, Arch, L, R, RelocBinder, Tls, NewObs>
    where
        NewObs: RelocationObserver<Arch>,
    {
        LinkerRun {
            linker: self.linker,
            pipeline: self.pipeline,
            observer,
            scratch_order: self.scratch_order,
        }
    }

    /// Reconfigures the scan-first pipeline for this run.
    #[inline]
    pub fn map_pipeline(
        self,
        configure: impl FnOnce(LinkPipeline<'pipe, Arch, Tls>) -> LinkPipeline<'pipe, Arch, Tls>,
    ) -> Self {
        let Self {
            linker,
            pipeline,
            observer,
            scratch_order,
        } = self;

        Self {
            linker,
            pipeline: configure(pipeline),
            observer,
            scratch_order,
        }
    }
}

#[allow(private_bounds)]
impl<'run, 'pipe, D: Send + Sync + 'static, Tls, Arch, M, Exec, Resolver, RelocBinder, Obs>
    LinkerRun<'run, 'pipe, Arch, Loader<D, Tls, Arch, M, Exec>, Resolver, RelocBinder, Tls, Obs>
where
    D: Default + Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
    ElfRelType<Arch>: ByteRepr,
    Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch> + RelocationObserver<Arch>,
    Resolver: KeyResolver<Arch, Tls>,
    RelocBinder: LazyBinder<Arch> + Clone,
{
    /// Loads, commits, and initializes one module and its dependency group.
    ///
    /// Initialization failure is rolled back before the error is returned. Use
    /// the staged API when the caller needs to choose another failure policy.
    pub fn load<Meta>(
        &mut self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        root: Resolver::Root,
    ) -> Result<LoadResult>
    where
        Meta: Default,
    {
        self.load_with_caller(context, root, None)
    }

    /// Loads one root on behalf of a module already committed to `context`.
    ///
    /// Initialization failure is rolled back before the error is returned.
    pub fn load_from<Meta>(
        &mut self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        root: Resolver::Root,
        caller: ModuleId,
    ) -> Result<LoadResult>
    where
        Meta: Default,
    {
        self.load_with_caller(context, root, Some(caller))
    }

    fn load_with_caller<Meta>(
        &mut self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        root: Resolver::Root,
        caller: Option<ModuleId>,
    ) -> Result<LoadResult>
    where
        Meta: Default,
    {
        let prepared = self.prepare_load_with_caller(context, root, caller)?;
        let relocated = self.relocate(prepared)?;
        let published = relocated.publish(context)?;
        match published.initialize() {
            Ok(result) => Ok(result),
            Err(failed) => Err(failed.rollback(context)),
        }
    }

    /// Resolves and maps one module group without executing target code.
    pub fn prepare_load<Meta>(
        &mut self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        root: Resolver::Root,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>> {
        self.prepare_load_with_caller(context, root, None)
    }

    /// Resolves and maps one caller-relative root without executing target code.
    pub fn prepare_load_from<Meta>(
        &mut self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        root: Resolver::Root,
        caller: ModuleId,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>> {
        self.prepare_load_with_caller(context, root, Some(caller))
    }

    fn prepare_load_with_caller<Meta>(
        &mut self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        root: Resolver::Root,
        caller: Option<ModuleId>,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>> {
        context
            .committed
            .ensure_domain(self.linker.loader.domain_id())?;
        let caller = caller
            .map(|id| -> Result<ModuleSlot> {
                let slot = context.committed.module_slot(id)?;
                if !context.committed.contains_module(slot) {
                    return Err(
                        LinkerError::context(LinkContextError::ModuleNotCommitted { id }).into(),
                    );
                }
                Ok(slot)
            })
            .transpose()?;
        let key = self.linker.resolver.root_key(&root);
        if let Some(prepared) = PreparedLoad::visible(context, &key) {
            return Ok(prepared);
        }
        let linker = self.linker;
        let mut session = ResolveSession::new();
        let tokens = context.search_paths.tokens();
        let mut loader = linker
            .loader
            .run()
            .with_search_path_pool(&mut context.search_paths)
            .with_observer(&mut self.observer);
        let mut resolve_context =
            LoadResolveContext::new(&mut context.committed, &mut session, tokens);
        let resolved = resolve_context.resolve_root(root, caller, &linker.resolver)?;
        let root = resolve_context.stage(resolved, caller, &mut loader)?;
        resolve_context.bind_key(key, root);
        resolve_context.resolve_pending(root, &mut loader, &linker.resolver)?;
        Ok(PreparedLoad::new(root, session, None, context))
    }

    /// Loads, commits, and initializes a pre-mapped root dynamic image.
    ///
    /// Initialization failure is rolled back before the error is returned.
    pub fn load_mapped_root<Meta>(
        &mut self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        key: ModuleKey,
        raw: RawDynamic<D, Arch, M::Region, Tls>,
    ) -> Result<LoadResult>
    where
        Meta: Default,
    {
        let prepared = self.prepare_mapped_root(context, key, raw)?;
        let relocated = self.relocate(prepared)?;
        let published = relocated.publish(context)?;
        match published.initialize() {
            Ok(result) => Ok(result),
            Err(failed) => Err(failed.rollback(context)),
        }
    }

    /// Resolves dependencies for a pre-mapped root without relocating it.
    pub fn prepare_mapped_root<Meta>(
        &mut self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        key: ModuleKey,
        raw: RawDynamic<D, Arch, M::Region, Tls>,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>> {
        context
            .committed
            .ensure_domain(self.linker.loader.domain_id())?;
        context
            .committed
            .ensure_domain(raw.core_ref().domain_id())?;
        if let Some(prepared) = PreparedLoad::visible(context, &key) {
            return Ok(prepared);
        }

        let linker = self.linker;
        let mut session = ResolveSession::new();
        let source = raw.core_ref().source_id();
        let key = context.committed.intern_key(key);
        if let Some(root) = context.committed.module_for_source(source) {
            session.track(root, context.committed.generation(root));
            session.stage_alias(key, root);
            return Ok(PreparedLoad::new(root, session, None, context));
        }
        let root = context.committed.intern_module(key);
        let generation = context.committed.generation(root);
        let alias = raw
            .core_ref()
            .search()
            .and_then(ModuleSearch::soname)
            .map(ModuleKey::from);
        session.stage_dynamic(root, generation, raw, None);
        session.stage_source(source, root);
        if let Some(alias) = alias {
            let alias = context.committed.intern_key(alias);
            session.stage_alias(alias, root);
        }
        let tokens = context.search_paths.tokens();
        let mut loader = linker
            .loader
            .run()
            .with_search_path_pool(&mut context.search_paths)
            .with_observer(&mut self.observer);
        let mut resolve_context =
            LoadResolveContext::new(&mut context.committed, &mut session, tokens);
        resolve_context.resolve_pending(root, &mut loader, &linker.resolver)?;
        Ok(PreparedLoad::new(root, session, None, context))
    }

    /// Relocates a prepared module group without borrowing its link context.
    pub fn relocate(
        &mut self,
        prepared: PreparedLoad<D, Arch, M::Region, Tls>,
    ) -> Result<RelocatedLoad<D, Arch, M::Region, Tls>> {
        let PreparedLoad {
            context,
            root: root_slot,
            session,
            relocation,
            mapped_runtime,
        } = prepared;

        let mut session = LoadSession::from_resolve(session);

        if let Some(relocation) = relocation {
            self.relocate_pending_modules(
                root_slot,
                &relocation.local,
                &relocation.global,
                &relocation.symbols,
                &mut session,
            )?;
        }

        if let Some(mapped_runtime) = mapped_runtime.as_ref() {
            mapped_runtime.protect()?;
        }

        Ok(RelocatedLoad {
            context,
            root: root_slot,
            session,
        })
    }

    fn relocate_pending_modules(
        &mut self,
        root: ModuleSlot,
        local: &ModuleScope<Arch, Tls>,
        global: &GlobalScope<Arch, Tls>,
        symbols: &Arc<SymbolRegistry<Arch, Tls>>,
        session: &mut LoadSession<D, Arch, M::Region, Tls>,
    ) -> Result<()> {
        let mut order = mem::take(&mut self.scratch_order);
        session.build_lifecycle_order(root, &mut order);
        let scope = LookupScope::from_group(local.clone()).with_global(global.clone());

        let result = (|| {
            for id in order.drain(..) {
                if let Some(entry) = session.take_pending_dynamic(id) {
                    let (raw, direct_deps) = entry.into_parts();
                    let direct_deps =
                        direct_deps.expect("missing resolved dependencies while relocating");
                    let mut event = LinkerRelocationEvent::new(raw, scope.clone());
                    self.observer.on_relocation(&mut event)?;
                    let (raw, scope, binding) = event.into_parts();
                    let loaded = self
                        .linker
                        .relocator
                        .run(raw)
                        .lookup_scope(scope)
                        .symbol_registry(Arc::clone(symbols))
                        .binding(binding)
                        .observer(&mut self.observer)
                        .relocate()?;
                    session.push_ready(id, loaded, direct_deps);
                } else {
                    session.mark_module_ready(id);
                }
                session.push_lifecycle(id);
            }
            Ok(())
        })();

        self.scratch_order = order;
        result
    }
}

#[allow(private_bounds)]
impl<D: Send + Sync + 'static, Tls, Arch, M, Exec, Resolver, RelocBinder>
    Linker<Arch, Loader<D, Tls, Arch, M, Exec>, Resolver, RelocBinder, Tls>
where
    D: Default + Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
    ElfRelType<Arch>: ByteRepr,
    Resolver: KeyResolver<Arch, Tls>,
    RelocBinder: LazyBinder<Arch> + Clone,
{
    /// Loads one module into this linker's relocation domain.
    pub fn load<Meta>(
        &self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        root: Resolver::Root,
    ) -> Result<LoadResult>
    where
        Meta: Default,
    {
        self.run().load(context, root)
    }

    /// Loads one root on behalf of a module already committed to `context`.
    pub fn load_from<Meta>(
        &self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        root: Resolver::Root,
        caller: ModuleId,
    ) -> Result<LoadResult>
    where
        Meta: Default,
    {
        self.run().load_from(context, root, caller)
    }

    /// Loads a pre-mapped root dynamic image and resolves its dependencies.
    pub fn load_mapped_root<Meta>(
        &self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        key: ModuleKey,
        raw: RawDynamic<D, Arch, M::Region, Tls>,
    ) -> Result<LoadResult>
    where
        Meta: Default,
    {
        self.run().load_mapped_root(context, key, raw)
    }

    /// Discovers, plans, and loads one module through the scan-first path.
    pub fn load_scan_first<Meta>(
        &self,
        context: &mut LinkContext<Meta, Arch, Tls>,
        root: Resolver::Root,
    ) -> Result<LoadResult>
    where
        Meta: Default,
    {
        self.run().load_scan_first(context, root)
    }
}

/// A resolved and mapped load transaction that has not executed relocation.
#[must_use = "a prepared load must be relocated or dropped"]
pub struct PreparedLoad<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    context: ContextId,
    root: ModuleSlot,
    session: ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch, Tls>,
    relocation: Option<PreparedRelocation<Arch, Tls>>,
    mapped_runtime: Option<MappedRuntimeMemory<R>>,
}

struct PreparedRelocation<Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    local: ModuleScope<Arch, Tls>,
    global: GlobalScope<Arch, Tls>,
    symbols: Arc<SymbolRegistry<Arch, Tls>>,
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    PreparedLoad<D, Arch, R, Tls>
{
    pub(in crate::linker) fn visible<Meta>(
        context: &LinkContext<Meta, Arch, Tls>,
        key: &ModuleKey,
    ) -> Option<Self> {
        let root = context
            .committed
            .key_slot_for(key)
            .and_then(|key| context.committed.module_for_key(key))?;
        let mut session = ResolveSession::new();
        session.track(root, context.committed.generation(root));
        Some(Self::new(root, session, None, context))
    }

    pub(in crate::linker) fn new<Meta>(
        root: ModuleSlot,
        session: ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch, Tls>,
        mapped_runtime: Option<MappedRuntimeMemory<R>>,
        context: &LinkContext<Meta, Arch, Tls>,
    ) -> Self {
        let relocation = if session.pending_is_empty() {
            None
        } else {
            let local = session.build_scope(context);
            Some(PreparedRelocation {
                local,
                global: context.global.clone(),
                symbols: Arc::clone(&context.symbols),
            })
        };
        Self {
            context: context.context_id(),
            root,
            session,
            relocation,
            mapped_runtime,
        }
    }
}

/// A relocated load transaction ready to publish into its original context.
#[must_use = "a relocated load must be published or dropped"]
pub struct RelocatedLoad<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    context: ContextId,
    root: ModuleSlot,
    session: LoadSession<D, Arch, R, Tls>,
}

impl<D: Send + Sync + 'static, Arch, R, Tls> RelocatedLoad<D, Arch, R, Tls>
where
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
        context: &mut LinkContext<Meta, Arch, Tls>,
    ) -> Result<PublishedLoad<Arch, Tls>>
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

        let initializers = self.session.initializers().into_boxed_slice();
        let modules = self.session.commit_into(&mut context.committed)?;
        let root_id = context.committed.make_module_id(self.root);
        let lease = context.acquire(root_id)?;
        Ok(PublishedLoad {
            lease,
            modules,
            initializers,
        })
    }
}

/// A published module group whose initializers have not completed yet.
#[must_use = "a published load must be initialized or rolled back"]
pub struct PublishedLoad<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    lease: ModuleLease,
    modules: Box<[ModuleId]>,
    initializers: Box<[ModuleHandle<Arch, Tls>]>,
}

impl<Arch, Tls> fmt::Debug for PublishedLoad<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedLoad")
            .field("root_id", &self.lease.id())
            .field("modules", &self.modules)
            .field("pending_initializers", &self.initializers.len())
            .finish()
    }
}

impl<Arch, Tls> PublishedLoad<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Returns the published root module id.
    #[inline]
    pub const fn root(&self) -> ModuleId {
        self.lease.id()
    }

    /// Returns module ids published by this load operation in load order.
    #[inline]
    pub fn modules(&self) -> &[ModuleId] {
        &self.modules
    }

    /// Executes module initializers in dependency order.
    pub fn initialize(self) -> core::result::Result<LoadResult, FailedLoad<Arch, Tls>> {
        let result = self
            .initializers
            .iter()
            .try_for_each(|module| module.initialize());
        if let Err(error) = result {
            return Err(FailedLoad { error, load: self });
        }
        Ok(LoadResult::new(self.lease, self.modules))
    }

    /// Releases this publication and finalizes modules that become unreachable.
    pub fn rollback<Meta>(self, context: &mut LinkContext<Meta, Arch, Tls>) -> Result<()> {
        let expected = self.lease.id().context();
        if context.context_id() != expected {
            return Err(LinkerError::context(LinkContextError::ContextMismatch {
                expected,
                actual: context.context_id(),
            })
            .into());
        }

        context.release(self.lease)?;
        Ok(())
    }
}

/// A published load whose initialization failed.
///
/// Continuing execution requires rolling the load back. Runtimes that treat
/// initialization failure as fatal may inspect the error and terminate.
#[must_use = "a failed load must be rolled back or treated as fatal"]
pub struct FailedLoad<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    error: Error,
    load: PublishedLoad<Arch, Tls>,
}

impl<Arch, Tls> fmt::Debug for FailedLoad<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FailedLoad")
            .field("error", &self.error)
            .field("root_id", &self.load.lease.id())
            .finish()
    }
}

impl<Arch, Tls> FailedLoad<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Returns the initialization error.
    #[inline]
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Removes the published modules and returns the initialization error.
    pub fn rollback<Meta>(self, context: &mut LinkContext<Meta, Arch, Tls>) -> Error {
        match self.load.rollback(context) {
            Ok(()) => self.error,
            Err(error) => error,
        }
    }
}
