use crate::{
    Result,
    image::{ModuleHandle, ModuleScope, ModuleScopeBuilder},
    lazy::traits::{LazyBinder, SupportLazy},
    observer::RelocationObserver,
    relocation::{BindingMode, Relocatable, RelocateArgs, RelocationArch, RelocationHandler},
    runtime::{CodeExecutor, NativeCodeExecutor},
    sync::Arc,
    tls::TlsResolver,
};
use alloc::boxed::Box;
use core::marker::PhantomData;

/// A builder for configuring and executing relocation.
///
/// A relocator is obtained by calling `.relocator()` on a raw image returned by
/// [`crate::Loader`]. It lets you provide symbol lookup callbacks, dependency scope,
/// relocation handlers, and binding policy before finally calling `relocate()`.
///
/// # Examples
/// ```no_run
/// use elf_loader::{
///     Loader, Result,
///     image::{SyntheticSymbol, SyntheticModule},
/// };
///
/// fn main() -> Result<()> {
///     let mut loader = Loader::new();
///     let lib = loader.load_dylib("path/to/liba.so")?;
///     let host = SyntheticModule::new(
///         "__host",
///         [
///             SyntheticSymbol::function("malloc", 0x1234 as *const ()),
///             SyntheticSymbol::function("free", 0x5678 as *const ()),
///         ],
///     );
///
///     let relocated = lib
///         .relocator()
///         .scope([host])
///         .relocate()?;
///
///     let _ = relocated;
///     Ok(())
/// }
/// ```
pub struct Relocator<
    T,
    PreH,
    PostH,
    Arch: RelocationArch = crate::arch::NativeArch,
    Obs = (),
    Tls: TlsResolver<Arch> = (),
    ScopeState = ModuleScopeBuilder<Arch, Tls>,
> {
    object: T,
    scope: ScopeState,
    pre_handler: PreH,
    post_handler: PostH,
    observer: Obs,
    binding: BindingMode,
    executor: Option<Arc<dyn CodeExecutor<Arch>>>,
    lazy_binder: Arc<dyn LazyBinder<Arch>>,
    _tls: PhantomData<fn() -> Tls>,
}

impl<T, PreH, PostH, Arch, Obs, Tls, ScopeState> Clone
    for Relocator<T, PreH, PostH, Arch, Obs, Tls, ScopeState>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    T: Clone,
    PreH: Clone,
    PostH: Clone,
    Obs: Clone,
    ScopeState: Clone,
{
    fn clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            scope: self.scope.clone(),
            pre_handler: self.pre_handler.clone(),
            post_handler: self.post_handler.clone(),
            observer: self.observer.clone(),
            binding: self.binding,
            executor: self.executor.clone(),
            lazy_binder: self.lazy_binder.clone(),
            _tls: PhantomData,
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>>
    Relocator<(), (), (), Arch, (), Tls, ModuleScopeBuilder<Arch, Tls>>
{
    /// Creates a new empty `Relocator` configuration.
    pub fn new() -> Self {
        Self {
            object: (),
            scope: ModuleScopeBuilder::new(),
            pre_handler: (),
            post_handler: (),
            observer: (),
            binding: BindingMode::Default,
            executor: None,
            lazy_binder: Arc::from(Box::new(()) as Box<dyn LazyBinder<Arch>>),
            _tls: PhantomData,
        }
    }

    /// Switches an empty relocator configuration to a different target architecture.
    pub fn for_arch<NewArch: RelocationArch>(
        self,
    ) -> Relocator<(), (), (), NewArch, (), Tls, ModuleScopeBuilder<NewArch, Tls>>
    where
        Tls: TlsResolver<NewArch>,
    {
        Relocator::<(), (), (), NewArch, (), Tls, ModuleScopeBuilder<NewArch, Tls>> {
            object: self.object,
            scope: ModuleScopeBuilder::new(),
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            observer: self.observer,
            binding: self.binding,
            executor: None,
            lazy_binder: Arc::from(Box::new(()) as Box<dyn LazyBinder<NewArch>>),
            _tls: PhantomData,
        }
    }
}

impl<Arch: RelocationArch> Default for Relocator<(), (), (), Arch> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls>
    Relocator<T, PreH, PostH, Arch, Obs, Tls, ModuleScopeBuilder<Arch, Tls>>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
    Obs: RelocationObserver<Arch>,
{
    /// Replaces the current module scope used for symbol resolution.
    ///
    /// During relocation, modules are searched in the provided order.
    /// Scope entries are retained as dependencies of the relocated output.
    pub fn scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.scope.replace(scope);
        self
    }

    /// Replaces the current module scope with a shared scope owner.
    ///
    /// Scope entries are searched in order and retained as dependencies of the
    /// relocated output. The shared scope is used as-is; callers that need
    /// built-in symbols should include them in the provided scope.
    pub fn shared_scope(
        self,
        scope: ModuleScope<Arch, Tls>,
    ) -> Relocator<T, PreH, PostH, Arch, Obs, Tls, ModuleScope<Arch, Tls>> {
        Relocator::<T, PreH, PostH, Arch, Obs, Tls, ModuleScope<Arch, Tls>> {
            object: self.object,
            scope,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            observer: self.observer,
            binding: self.binding,
            executor: self.executor,
            lazy_binder: self.lazy_binder,
            _tls: PhantomData,
        }
    }

    /// Appends more modules to the symbol-resolution scope.
    ///
    /// Additional modules are searched after the existing
    /// scope entries. Scope entries are retained as dependencies of the
    /// relocated output.
    pub fn extend_scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.scope.extend(scope);
        self
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls, ScopeState>
    Relocator<T, PreH, PostH, Arch, Obs, Tls, ScopeState>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
    Obs: RelocationObserver<Arch>,
{
    /// Attaches an object and selects the user-data type carried by that object.
    pub fn with_object<U>(
        self,
        object: U,
    ) -> Relocator<U, PreH, PostH, Arch, Obs, Tls, ScopeState> {
        Relocator::<U, PreH, PostH, Arch, Obs, Tls, ScopeState> {
            object,
            scope: self.scope,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            observer: self.observer,
            binding: self.binding,
            executor: self.executor,
            lazy_binder: self.lazy_binder,
            _tls: PhantomData,
        }
    }

    /// Sets the relocation handler that runs before the built-in logic.
    ///
    /// This is useful for intercepting selected relocations or providing
    /// custom behavior before the default implementation runs.
    pub fn pre_handler<NewPreH>(
        self,
        handler: NewPreH,
    ) -> Relocator<T, NewPreH, PostH, Arch, Obs, Tls, ScopeState>
    where
        NewPreH: RelocationHandler<Arch>,
    {
        Relocator::<T, NewPreH, PostH, Arch, Obs, Tls, ScopeState> {
            object: self.object,
            scope: self.scope,
            pre_handler: handler,
            post_handler: self.post_handler,
            observer: self.observer,
            binding: self.binding,
            executor: self.executor,
            lazy_binder: self.lazy_binder,
            _tls: PhantomData,
        }
    }

    /// Sets the relocation handler that runs after the built-in logic.
    ///
    /// This handler is called only if the relocation was not already handled
    /// by the pre-handler or the default relocation logic.
    pub fn post_handler<NewPostH>(
        self,
        handler: NewPostH,
    ) -> Relocator<T, PreH, NewPostH, Arch, Obs, Tls, ScopeState>
    where
        NewPostH: RelocationHandler<Arch>,
    {
        Relocator::<T, PreH, NewPostH, Arch, Obs, Tls, ScopeState> {
            object: self.object,
            scope: self.scope,
            pre_handler: self.pre_handler,
            post_handler: handler,
            observer: self.observer,
            binding: self.binding,
            executor: self.executor,
            lazy_binder: self.lazy_binder,
            _tls: PhantomData,
        }
    }

    /// Sets the runtime-linker observer used during relocation.
    pub fn observer<NewObs>(
        self,
        observer: NewObs,
    ) -> Relocator<T, PreH, PostH, Arch, NewObs, Tls, ScopeState>
    where
        NewObs: RelocationObserver<Arch>,
    {
        Relocator::<T, PreH, PostH, Arch, NewObs, Tls, ScopeState> {
            object: self.object,
            scope: self.scope,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            observer,
            binding: self.binding,
            executor: self.executor,
            lazy_binder: self.lazy_binder,
            _tls: PhantomData,
        }
    }

    /// Overrides the relocation binding mode.
    pub fn binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }

    /// Overrides the runtime-code executor used for init, fini and IFUNC.
    pub fn executor<E>(mut self, executor: E) -> Self
    where
        E: CodeExecutor<Arch>,
    {
        self.executor = Some(Arc::from(Box::new(executor) as Box<dyn CodeExecutor<Arch>>));
        self
    }

    #[inline]
    /// Updates the relocation binding mode in place.
    pub fn set_binding(&mut self, binding: BindingMode) {
        self.binding = binding;
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls>
    Relocator<T, PreH, PostH, Arch, Obs, Tls, ModuleScopeBuilder<Arch, Tls>>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
    Obs: RelocationObserver<Arch>,
{
    /// Executes relocation with the current configuration.
    ///
    /// This consumes the builder, resolves relocations, retains the configured
    /// relocation scope as dependencies, and returns the final loaded image.
    ///
    /// The target architecture is selected automatically from the relocated
    /// image: native images use
    /// [`crate::arch::NativeArch`] (the default) and run target init arrays,
    /// IFUNC resolvers,
    /// lazy-binding trampolines, and TLS resolver stubs as usual;
    /// cross-architecture images avoid host execution of target code; call
    /// [`Relocator::executor`] before relocation when guest runtime hooks must
    /// be executed.
    pub fn relocate<D>(self) -> Result<<T as Relocatable<D>>::Output>
    where
        D: 'static,
        T: Relocatable<D, Arch = Arch, Tls = Tls>,
    {
        let Self {
            object,
            scope,
            pre_handler,
            post_handler,
            mut observer,
            binding,
            executor,
            lazy_binder,
            ..
        } = self;
        let executor: Arc<dyn CodeExecutor<Arch>> = executor.unwrap_or_else(|| {
            Arc::from(Box::new(NativeCodeExecutor) as Box<dyn CodeExecutor<Arch>>)
        });

        object.relocate(RelocateArgs {
            scope: scope.into_scope(),
            binding,
            executor,
            lazy_binder,
            pre_handler: &pre_handler,
            post_handler: &post_handler,
            observer: &mut observer,
        })
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls>
    Relocator<T, PreH, PostH, Arch, Obs, Tls, ModuleScope<Arch, Tls>>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
    Obs: RelocationObserver<Arch>,
{
    /// Executes relocation with the current configuration.
    ///
    /// This consumes the builder, resolves relocations, retains the configured
    /// relocation scope as dependencies, and returns the final loaded image.
    ///
    /// The target architecture is selected automatically from the relocated
    /// image: native images use
    /// [`crate::arch::NativeArch`] (the default) and run target init arrays,
    /// IFUNC resolvers,
    /// lazy-binding trampolines, and TLS resolver stubs as usual;
    /// cross-architecture images avoid host execution of target code; call
    /// [`Relocator::executor`] before relocation when guest runtime hooks must
    /// be executed.
    pub fn relocate<D>(self) -> Result<<T as Relocatable<D>>::Output>
    where
        D: 'static,
        T: Relocatable<D, Arch = Arch, Tls = Tls>,
    {
        let Self {
            object,
            scope,
            pre_handler,
            post_handler,
            mut observer,
            binding,
            executor,
            lazy_binder,
            ..
        } = self;
        let executor: Arc<dyn CodeExecutor<Arch>> = executor.unwrap_or_else(|| {
            Arc::from(Box::new(NativeCodeExecutor) as Box<dyn CodeExecutor<Arch>>)
        });

        object.relocate(RelocateArgs {
            scope,
            binding,
            executor,
            lazy_binder,
            pre_handler: &pre_handler,
            post_handler: &post_handler,
            observer: &mut observer,
        })
    }
}

impl<T, PreH, PostH, Arch, Obs, Tls, ScopeState>
    Relocator<T, PreH, PostH, Arch, Obs, Tls, ScopeState>
where
    T: SupportLazy,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
    Obs: RelocationObserver<Arch>,
{
    /// Forces eager binding.
    pub fn eager(mut self) -> Self {
        self.binding = BindingMode::Eager;
        self
    }

    /// Overrides the lazy PLT binder used to prepare runtime binding.
    pub fn lazy_binder<B>(mut self, binder: B) -> Self
    where
        B: LazyBinder<Arch>,
    {
        self.lazy_binder = Arc::from(Box::new(binder) as Box<dyn LazyBinder<Arch>>);
        self
    }

    /// Forces lazy binding.
    pub fn lazy(mut self) -> Self {
        self.binding = BindingMode::Lazy;
        self
    }
}
