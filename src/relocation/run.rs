use crate::{
    Relocator, Result,
    arch::NativeArch,
    image::{GlobalScope, LookupScope, ModuleHandle},
    lazy::{LazyBinder, SupportLazy},
    observer::RelocationObserver,
    relocation::{
        BindingMode, LookupOrder, Relocatable, RelocateArgs, RelocationArch, SymbolRegistry,
    },
    sync::Arc,
    tls::TlsResolver,
};

/// Per-image relocation run state.
///
/// A run owns the raw image being relocated and the scope being assembled for
/// that image. It consumes itself when [`relocate`](Self::relocate) is called.
pub struct RelocatorRun<
    'cfg,
    T,
    Arch: RelocationArch = NativeArch,
    Obs = (),
    Tls: TlsResolver<Arch> = (),
    Binder = (),
> {
    object: T,
    scope: LookupScope<Arch, Tls>,
    global: Option<GlobalScope<Arch, Tls>>,
    observer: Obs,
    binding: BindingMode,
    lookup_order: LookupOrder,
    symbols: Option<Arc<SymbolRegistry<Arch, Tls>>>,
    relocator: &'cfg Relocator<Binder>,
}

impl<Binder> Relocator<Binder> {
    /// Starts a relocation run using this reusable configuration.
    #[inline]
    pub fn run<D: Send + Sync + 'static, T, Arch, Tls>(
        &self,
        object: T,
    ) -> RelocatorRun<'_, T, Arch, (), Tls, Binder>
    where
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
        T: Relocatable<D, Arch = Arch, Tls = Tls>,
    {
        let domain = object.domain_id();
        RelocatorRun {
            object,
            scope: LookupScope::empty(domain),
            global: None,
            observer: (),
            binding: BindingMode::Default,
            lookup_order: LookupOrder::GlobalFirst,
            symbols: None,
            relocator: self,
        }
    }
}

impl<'cfg, T, Arch, Obs, Tls, Binder> Clone for RelocatorRun<'cfg, T, Arch, Obs, Tls, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    T: Clone,
    Obs: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            scope: self.scope.clone(),
            global: self.global.clone(),
            observer: self.observer.clone(),
            binding: self.binding,
            lookup_order: self.lookup_order,
            symbols: self.symbols.clone(),
            relocator: self.relocator,
        }
    }
}

impl<'cfg, T, Arch, Obs, Tls, Binder> RelocatorRun<'cfg, T, Arch, Obs, Tls, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Binder: LazyBinder<Arch>,
{
    /// Sets the runtime-linker observer used during relocation.
    pub fn observer<NewObs>(
        self,
        observer: NewObs,
    ) -> RelocatorRun<'cfg, T, Arch, NewObs, Tls, Binder>
    where
        NewObs: RelocationObserver<Arch>,
    {
        let RelocatorRun {
            object,
            scope,
            global,
            binding,
            lookup_order,
            symbols,
            relocator,
            observer: _,
        } = self;

        RelocatorRun {
            object,
            scope,
            global,
            observer,
            binding,
            lookup_order,
            symbols,
            relocator,
        }
    }

    /// Overrides the relocation binding mode.
    #[inline]
    pub fn binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }

    /// Sets precedence between the local and context-global lookup scopes.
    #[inline]
    pub fn lookup_order(mut self, order: LookupOrder) -> Self {
        self.lookup_order = order;
        self
    }

    #[inline]
    pub(crate) fn symbol_registry(mut self, symbols: Arc<SymbolRegistry<Arch, Tls>>) -> Self {
        self.symbols = Some(symbols);
        self
    }

    /// Uses a [`LinkContext`](crate::LinkContext) global symbol scope.
    ///
    /// The shared handle is retained only for the relocation run. Deferred
    /// binding stores a weak reference and therefore does not keep the context
    /// or unrelated global modules alive.
    #[inline]
    pub fn global_scope(mut self, global: &GlobalScope<Arch, Tls>) -> Self {
        self.global = Some(global.clone());
        self
    }

    /// Replaces the current module scope used for symbol resolution.
    pub fn scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.scope.replace(scope);
        self.global = None;
        self.symbols = None;
        self
    }

    /// Replaces the current module scope with a prepared lookup scope.
    ///
    /// Unlike [`scope`](Self::scope), this preserves the scope's module-group
    /// boundaries.
    pub fn lookup_scope(mut self, scope: LookupScope<Arch, Tls>) -> Self {
        self.scope = scope;
        self.global = None;
        self.symbols = None;
        self
    }

    /// Appends more modules to the symbol-resolution scope.
    pub fn extend_scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.scope.extend(scope);
        self
    }
}

impl<'cfg, T, Arch, Obs, Tls, Binder> RelocatorRun<'cfg, T, Arch, Obs, Tls, Binder>
where
    T: SupportLazy,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Binder: LazyBinder<Arch>,
{
    /// Forces eager binding.
    #[inline]
    pub fn eager(mut self) -> Self {
        self.binding = BindingMode::Eager;
        self
    }

    /// Forces lazy binding.
    #[inline]
    pub fn lazy(mut self) -> Self {
        self.binding = BindingMode::Lazy;
        self
    }
}

impl<'cfg, T, Arch, Obs, Tls, Binder> RelocatorRun<'cfg, T, Arch, Obs, Tls, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Obs: RelocationObserver<Arch>,
    Binder: LazyBinder<Arch>,
{
    /// Executes relocation with the current run state.
    pub fn relocate<D>(self) -> Result<<T as Relocatable<D>>::Output>
    where
        D: Send + Sync + 'static,
        T: Relocatable<D, Arch = Arch, Tls = Tls>,
    {
        let RelocatorRun {
            object,
            scope,
            global,
            mut observer,
            binding,
            lookup_order,
            symbols,
            relocator,
        } = self;

        object.relocate(RelocateArgs {
            scope,
            global,
            symbols,
            binding,
            lookup_order,
            run_init: relocator.run_init,
            lazy_binder: &relocator.lazy_binder,
            observer: &mut observer,
        })
    }
}
