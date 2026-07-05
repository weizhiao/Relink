use crate::{
    Result,
    const_builder::NoDrop,
    image::{ModuleHandle, ModuleScope, ModuleScopeBuilder},
    lazy::traits::{LazyBinder, SupportLazy},
    observer::RelocationObserver,
    relocation::{BindingMode, Relocatable, RelocateArgs, RelocationArch, RelocationHandler},
    tls::TlsResolver,
};
use core::{marker::PhantomData, mem::MaybeUninit, ptr};

/// Reusable relocation configuration.
///
/// A `Relocator` stores the stable parts of relocation policy: relocation
/// handlers, an observer template, binding mode, and lazy binder. Attach a raw
/// image with [`Relocator::run`] or [`Relocator::with_object`] to create a
/// [`RelocatorRun`] that owns per-run state such as the object and symbol scope.
pub struct Relocator<
    PreH = (),
    PostH = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    Obs = (),
    Tls: TlsResolver<Arch> = (),
    Binder = (),
> {
    pre_handler: PreH,
    post_handler: PostH,
    observer: Obs,
    binding: BindingMode,
    lazy_binder: Binder,
    _tls: PhantomData<fn() -> (Arch, Tls)>,
}

struct RelocatorFields<PreH, PostH, Obs, Binder> {
    pre_handler: NoDrop<PreH>,
    post_handler: NoDrop<PostH>,
    observer: NoDrop<Obs>,
    binding: BindingMode,
    lazy_binder: NoDrop<Binder>,
}

/// Per-image relocation run state.
///
/// A run owns the raw image being relocated and the scope being assembled for
/// that image. It consumes itself when [`relocate`](Self::relocate) is called.
pub struct RelocatorRun<
    T,
    PreH = (),
    PostH = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    Obs = (),
    Tls: TlsResolver<Arch> = (),
    ScopeState = ModuleScopeBuilder<Arch, Tls>,
    Binder = (),
> {
    object: T,
    scope: ScopeState,
    relocator: Relocator<PreH, PostH, Arch, Obs, Tls, Binder>,
}

impl<PreH, PostH, Arch, Obs, Tls, Binder> Clone for Relocator<PreH, PostH, Arch, Obs, Tls, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    PreH: Clone,
    PostH: Clone,
    Obs: Clone,
    Binder: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            pre_handler: self.pre_handler.clone(),
            post_handler: self.post_handler.clone(),
            observer: self.observer.clone(),
            binding: self.binding,
            lazy_binder: self.lazy_binder.clone(),
            _tls: PhantomData,
        }
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls, ScopeState, Binder> Clone
    for RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ScopeState, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    T: Clone,
    ScopeState: Clone,
    PreH: Clone,
    PostH: Clone,
    Obs: Clone,
    Binder: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            scope: self.scope.clone(),
            relocator: self.relocator.clone(),
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Relocator<(), (), Arch, (), Tls, ()> {
    /// Creates a new empty relocation configuration.
    #[inline]
    pub const fn new() -> Self {
        Self {
            pre_handler: (),
            post_handler: (),
            observer: (),
            binding: BindingMode::Default,
            lazy_binder: (),
            _tls: PhantomData,
        }
    }

    /// Switches an empty relocator configuration to a different target architecture.
    #[inline]
    pub const fn for_arch<NewArch: RelocationArch>(self) -> Relocator<(), (), NewArch, (), Tls, ()>
    where
        Tls: TlsResolver<NewArch>,
    {
        Relocator::<(), (), NewArch, (), Tls, ()> {
            pre_handler: (),
            post_handler: (),
            observer: (),
            binding: self.binding,
            lazy_binder: (),
            _tls: PhantomData,
        }
    }
}

impl<Arch: RelocationArch> Default for Relocator<(), (), Arch> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<PreH, PostH, Arch, Obs, Tls, Binder> Relocator<PreH, PostH, Arch, Obs, Tls, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Binder: LazyBinder<Arch>,
{
    #[inline]
    const fn into_fields(self) -> RelocatorFields<PreH, PostH, Obs, Binder> {
        let this = MaybeUninit::new(self);
        let this = this.as_ptr();

        // SAFETY: `this` points at the fully initialized `self` stored inside
        // `MaybeUninit`, so every field read below is initialized and aligned.
        // Discarded fields are only discarded by const builders under a `Copy`
        // bound, so bypassing their destructor cannot skip meaningful cleanup.
        unsafe {
            RelocatorFields {
                pre_handler: NoDrop::read(ptr::addr_of!((*this).pre_handler)),
                post_handler: NoDrop::read(ptr::addr_of!((*this).post_handler)),
                observer: NoDrop::read(ptr::addr_of!((*this).observer)),
                binding: ptr::read(ptr::addr_of!((*this).binding)),
                lazy_binder: NoDrop::read(ptr::addr_of!((*this).lazy_binder)),
            }
        }
    }

    /// Starts a relocation run by cloning this reusable configuration.
    #[inline]
    pub fn run<T>(
        &self,
        object: T,
    ) -> RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ModuleScopeBuilder<Arch, Tls>, Binder>
    where
        PreH: Clone,
        PostH: Clone,
        Obs: Clone,
        Binder: Clone,
    {
        self.clone().with_object(object)
    }

    /// Attaches an object and starts a relocation run.
    #[inline]
    pub fn with_object<T>(
        self,
        object: T,
    ) -> RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ModuleScopeBuilder<Arch, Tls>, Binder> {
        RelocatorRun {
            object,
            scope: ModuleScopeBuilder::new(),
            relocator: self,
        }
    }

    /// Sets the relocation handler that runs before the built-in logic.
    pub const fn pre_handler<NewPreH>(
        self,
        handler: NewPreH,
    ) -> Relocator<NewPreH, PostH, Arch, Obs, Tls, Binder>
    where
        PreH: Copy,
        NewPreH: RelocationHandler<Arch>,
    {
        let RelocatorFields {
            post_handler,
            observer,
            binding,
            lazy_binder,
            ..
        } = self.into_fields();

        Relocator {
            pre_handler: handler,
            post_handler: post_handler.into_inner(),
            observer: observer.into_inner(),
            binding,
            lazy_binder: lazy_binder.into_inner(),
            _tls: PhantomData,
        }
    }

    /// Sets the relocation handler that runs after the built-in logic.
    pub const fn post_handler<NewPostH>(
        self,
        handler: NewPostH,
    ) -> Relocator<PreH, NewPostH, Arch, Obs, Tls, Binder>
    where
        PostH: Copy,
        NewPostH: RelocationHandler<Arch>,
    {
        let RelocatorFields {
            pre_handler,
            observer,
            binding,
            lazy_binder,
            ..
        } = self.into_fields();

        Relocator {
            pre_handler: pre_handler.into_inner(),
            post_handler: handler,
            observer: observer.into_inner(),
            binding,
            lazy_binder: lazy_binder.into_inner(),
            _tls: PhantomData,
        }
    }

    /// Sets the runtime-linker observer used during relocation.
    pub const fn observer<NewObs>(
        self,
        observer: NewObs,
    ) -> Relocator<PreH, PostH, Arch, NewObs, Tls, Binder>
    where
        Obs: Copy,
        NewObs: RelocationObserver<Arch>,
    {
        let RelocatorFields {
            pre_handler,
            post_handler,
            binding,
            lazy_binder,
            ..
        } = self.into_fields();

        Relocator {
            pre_handler: pre_handler.into_inner(),
            post_handler: post_handler.into_inner(),
            observer,
            binding,
            lazy_binder: lazy_binder.into_inner(),
            _tls: PhantomData,
        }
    }

    /// Overrides the relocation binding mode.
    #[inline]
    pub const fn binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }

    /// Updates the relocation binding mode in place.
    #[inline]
    pub const fn set_binding(&mut self, binding: BindingMode) {
        self.binding = binding;
    }

    /// Forces eager binding.
    #[inline]
    pub const fn eager(mut self) -> Self {
        self.binding = BindingMode::Eager;
        self
    }

    /// Overrides the lazy PLT binder used to prepare runtime binding.
    pub const fn lazy_binder<NewBinder>(
        self,
        binder: NewBinder,
    ) -> Relocator<PreH, PostH, Arch, Obs, Tls, NewBinder>
    where
        Binder: Copy,
        NewBinder: LazyBinder<Arch>,
    {
        let RelocatorFields {
            pre_handler,
            post_handler,
            observer,
            binding,
            ..
        } = self.into_fields();

        Relocator {
            pre_handler: pre_handler.into_inner(),
            post_handler: post_handler.into_inner(),
            observer: observer.into_inner(),
            binding,
            lazy_binder: binder,
            _tls: PhantomData,
        }
    }

    /// Forces lazy binding.
    #[inline]
    pub const fn lazy(mut self) -> Self {
        self.binding = BindingMode::Lazy;
        self
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls, ScopeState, Binder>
    RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ScopeState, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Binder: LazyBinder<Arch>,
{
    /// Sets the relocation handler that runs before the built-in logic.
    pub fn pre_handler<NewPreH>(
        self,
        handler: NewPreH,
    ) -> RelocatorRun<T, NewPreH, PostH, Arch, Obs, Tls, ScopeState, Binder>
    where
        NewPreH: RelocationHandler<Arch>,
    {
        let RelocatorRun {
            object,
            scope,
            relocator,
        } = self;
        let Relocator {
            post_handler,
            observer,
            binding,
            lazy_binder,
            ..
        } = relocator;

        RelocatorRun {
            object,
            scope,
            relocator: Relocator {
                pre_handler: handler,
                post_handler,
                observer,
                binding,
                lazy_binder,
                _tls: PhantomData,
            },
        }
    }

    /// Sets the relocation handler that runs after the built-in logic.
    pub fn post_handler<NewPostH>(
        self,
        handler: NewPostH,
    ) -> RelocatorRun<T, PreH, NewPostH, Arch, Obs, Tls, ScopeState, Binder>
    where
        NewPostH: RelocationHandler<Arch>,
    {
        let RelocatorRun {
            object,
            scope,
            relocator,
        } = self;
        let Relocator {
            pre_handler,
            observer,
            binding,
            lazy_binder,
            ..
        } = relocator;

        RelocatorRun {
            object,
            scope,
            relocator: Relocator {
                pre_handler,
                post_handler: handler,
                observer,
                binding,
                lazy_binder,
                _tls: PhantomData,
            },
        }
    }

    /// Sets the runtime-linker observer used during relocation.
    pub fn observer<NewObs>(
        self,
        observer: NewObs,
    ) -> RelocatorRun<T, PreH, PostH, Arch, NewObs, Tls, ScopeState, Binder>
    where
        NewObs: RelocationObserver<Arch>,
    {
        let RelocatorRun {
            object,
            scope,
            relocator,
        } = self;
        let Relocator {
            pre_handler,
            post_handler,
            binding,
            lazy_binder,
            ..
        } = relocator;

        RelocatorRun {
            object,
            scope,
            relocator: Relocator {
                pre_handler,
                post_handler,
                observer,
                binding,
                lazy_binder,
                _tls: PhantomData,
            },
        }
    }

    /// Overrides the relocation binding mode.
    #[inline]
    pub fn binding(mut self, binding: BindingMode) -> Self {
        self.relocator.binding = binding;
        self
    }

    /// Updates the relocation binding mode in place.
    #[inline]
    pub fn set_binding(&mut self, binding: BindingMode) {
        self.relocator.binding = binding;
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls, Binder>
    RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ModuleScopeBuilder<Arch, Tls>, Binder>
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
    ) -> RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ModuleScope<Arch, Tls>, Binder> {
        RelocatorRun {
            object: self.object,
            scope,
            relocator: self.relocator,
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

impl<T, PreH, PostH, Arch, Obs, Tls, ScopeState, Binder>
    RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ScopeState, Binder>
where
    T: SupportLazy,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Binder: LazyBinder<Arch>,
{
    /// Forces eager binding.
    #[inline]
    pub fn eager(mut self) -> Self {
        self.relocator.binding = BindingMode::Eager;
        self
    }

    /// Overrides the lazy PLT binder used to prepare runtime binding.
    pub fn lazy_binder<NewBinder>(
        self,
        binder: NewBinder,
    ) -> RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ScopeState, NewBinder>
    where
        NewBinder: LazyBinder<Arch>,
    {
        let RelocatorRun {
            object,
            scope,
            relocator,
        } = self;
        let Relocator {
            pre_handler,
            post_handler,
            observer,
            binding,
            ..
        } = relocator;

        RelocatorRun {
            object,
            scope,
            relocator: Relocator {
                pre_handler,
                post_handler,
                observer,
                binding,
                lazy_binder: binder,
                _tls: PhantomData,
            },
        }
    }

    /// Forces lazy binding.
    #[inline]
    pub fn lazy(mut self) -> Self {
        self.relocator.binding = BindingMode::Lazy;
        self
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls, Binder>
    RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ModuleScopeBuilder<Arch, Tls>, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
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
            relocator,
        } = self;
        let Relocator {
            pre_handler,
            post_handler,
            mut observer,
            binding,
            lazy_binder,
            ..
        } = relocator;

        object.relocate(RelocateArgs {
            scope: scope.into_scope(),
            binding,
            lazy_binder: &lazy_binder,
            pre_handler: &pre_handler,
            post_handler: &post_handler,
            observer: &mut observer,
        })
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls, Binder>
    RelocatorRun<T, PreH, PostH, Arch, Obs, Tls, ModuleScope<Arch, Tls>, Binder>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
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
            relocator,
        } = self;
        let Relocator {
            pre_handler,
            post_handler,
            mut observer,
            binding,
            lazy_binder,
            ..
        } = relocator;

        object.relocate(RelocateArgs {
            scope,
            binding,
            lazy_binder: &lazy_binder,
            pre_handler: &pre_handler,
            post_handler: &post_handler,
            observer: &mut observer,
        })
    }
}
