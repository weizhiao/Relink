use crate::{
    Relocator, Result,
    image::{ModuleHandle, ModuleScope, ModuleScopeBuilder},
    lazy::traits::{LazyBinder, SupportLazy},
    observer::RelocationObserver,
    relocation::{BindingMode, Relocatable, RelocateArgs, RelocationArch},
    tls::TlsResolver,
};
use core::marker::PhantomData;

/// Per-image relocation run state.
///
/// A run owns the raw image being relocated and the scope being assembled for
/// that image. It consumes itself when [`relocate`](Self::relocate) is called.
pub struct RelocatorRun<
    'cfg,
    T,
    Arch: RelocationArch = crate::arch::NativeArch,
    Obs = (),
    Tls: TlsResolver<Arch> = (),
    ScopeState = ModuleScopeBuilder<Arch, Tls>,
    Binder = (),
> {
    object: T,
    scope: ScopeState,
    observer: Obs,
    binding: BindingMode,
    relocator: &'cfg Relocator<Binder>,
    _target: PhantomData<fn() -> (Arch, Tls)>,
}

impl<Binder> Relocator<Binder> {
    /// Starts a relocation run using this reusable configuration.
    #[inline]
    pub fn run<D, T, Arch, Tls>(
        &self,
        object: T,
    ) -> RelocatorRun<'_, T, Arch, (), Tls, ModuleScopeBuilder<Arch, Tls>, Binder>
    where
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
        T: Relocatable<D, Arch = Arch, Tls = Tls>,
    {
        RelocatorRun {
            object,
            scope: ModuleScopeBuilder::new(),
            observer: (),
            binding: BindingMode::Default,
            relocator: self,
            _target: PhantomData,
        }
    }
}

impl<'cfg, T, Arch, Obs, Tls, ScopeState, Binder> Clone
    for RelocatorRun<'cfg, T, Arch, Obs, Tls, ScopeState, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    T: Clone,
    ScopeState: Clone,
    Obs: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            scope: self.scope.clone(),
            observer: self.observer.clone(),
            binding: self.binding,
            relocator: self.relocator,
            _target: PhantomData,
        }
    }
}

impl<'cfg, T, Arch, Obs, Tls, ScopeState, Binder>
    RelocatorRun<'cfg, T, Arch, Obs, Tls, ScopeState, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Binder: LazyBinder<Arch>,
{
    /// Sets the runtime-linker observer used during relocation.
    pub fn observer<NewObs>(
        self,
        observer: NewObs,
    ) -> RelocatorRun<'cfg, T, Arch, NewObs, Tls, ScopeState, Binder>
    where
        NewObs: RelocationObserver<Arch>,
    {
        let RelocatorRun {
            object,
            scope,
            binding,
            relocator,
            ..
        } = self;

        RelocatorRun {
            object,
            scope,
            observer,
            binding,
            relocator,
            _target: PhantomData,
        }
    }

    /// Overrides the relocation binding mode.
    #[inline]
    pub fn binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }

    /// Updates the relocation binding mode in place.
    #[inline]
    pub fn set_binding(&mut self, binding: BindingMode) {
        self.binding = binding;
    }
}

impl<'cfg, T, Arch, Obs, Tls, Binder>
    RelocatorRun<'cfg, T, Arch, Obs, Tls, ModuleScopeBuilder<Arch, Tls>, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Binder: LazyBinder<Arch>,
{
    /// Replaces the current module scope used for symbol resolution.
    pub fn scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.scope.replace(scope);
        self
    }

    /// Replaces the current module scope with a shared scope owner.
    pub fn shared_scope(
        self,
        scope: ModuleScope<Arch, Tls>,
    ) -> RelocatorRun<'cfg, T, Arch, Obs, Tls, ModuleScope<Arch, Tls>, Binder> {
        RelocatorRun {
            object: self.object,
            scope,
            observer: self.observer,
            binding: self.binding,
            relocator: self.relocator,
            _target: PhantomData,
        }
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

impl<'cfg, T, Arch, Obs, Tls, ScopeState, Binder>
    RelocatorRun<'cfg, T, Arch, Obs, Tls, ScopeState, Binder>
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

impl<'cfg, T, Arch, Obs, Tls, Binder>
    RelocatorRun<'cfg, T, Arch, Obs, Tls, ModuleScopeBuilder<Arch, Tls>, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Obs: RelocationObserver<Arch>,
    Binder: LazyBinder<Arch>,
{
    /// Executes relocation with the current run state.
    pub fn relocate<D>(self) -> Result<<T as Relocatable<D>>::Output>
    where
        D: 'static,
        T: Relocatable<D, Arch = Arch, Tls = Tls>,
    {
        let RelocatorRun {
            object,
            scope,
            mut observer,
            binding,
            relocator,
            ..
        } = self;

        object.relocate(RelocateArgs {
            scope: scope.into_scope(),
            binding,
            lazy_binder: &relocator.lazy_binder,
            observer: &mut observer,
        })
    }
}

impl<'cfg, T, Arch, Obs, Tls, Binder>
    RelocatorRun<'cfg, T, Arch, Obs, Tls, ModuleScope<Arch, Tls>, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Obs: RelocationObserver<Arch>,
    Binder: LazyBinder<Arch>,
{
    /// Executes relocation with the current run state.
    pub fn relocate<D>(self) -> Result<<T as Relocatable<D>>::Output>
    where
        D: 'static,
        T: Relocatable<D, Arch = Arch, Tls = Tls>,
    {
        let RelocatorRun {
            object,
            scope,
            mut observer,
            binding,
            relocator,
            ..
        } = self;

        object.relocate(RelocateArgs {
            scope,
            binding,
            lazy_binder: &relocator.lazy_binder,
            observer: &mut observer,
        })
    }
}
