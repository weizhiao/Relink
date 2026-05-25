use crate::{
    Result,
    image::{ModuleHandle, ModuleScope},
    observer::RelocationObserver,
    relocation::{
        BindingMode, Relocatable, RelocateArgs, RelocationArch, RelocationHandler, SupportLazy,
    },
};
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
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    Obs = (),
> {
    object: T,
    scope: ModuleScope<Arch>,
    pre_handler: PreH,
    post_handler: PostH,
    observer: Obs,
    binding: BindingMode,
    _marker: PhantomData<fn() -> (D, Arch)>,
}

impl<T, PreH, PostH, D: 'static, Arch, Obs> Clone for Relocator<T, PreH, PostH, D, Arch, Obs>
where
    Arch: RelocationArch,
    T: Clone,
    PreH: Clone,
    PostH: Clone,
    Obs: Clone,
{
    fn clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            scope: self.scope.clone(),
            pre_handler: self.pre_handler.clone(),
            post_handler: self.post_handler.clone(),
            observer: self.observer.clone(),
            binding: self.binding,
            _marker: PhantomData,
        }
    }
}

impl Relocator<(), (), (), ()> {
    /// Creates a new empty `Relocator` configuration.
    pub fn new() -> Self {
        Self {
            object: (),
            scope: ModuleScope::empty(),
            pre_handler: (),
            post_handler: (),
            observer: (),
            binding: BindingMode::Default,
            _marker: PhantomData,
        }
    }
}

impl<Arch: RelocationArch> Relocator<(), (), (), (), Arch> {
    /// Switches an empty relocator configuration to a different target architecture.
    pub fn for_arch<NewArch: RelocationArch>(self) -> Relocator<(), (), (), (), NewArch> {
        Relocator {
            object: self.object,
            scope: ModuleScope::empty(),
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            observer: self.observer,
            binding: self.binding,
            _marker: PhantomData,
        }
    }
}

impl<T, PreH, PostH, D: 'static, Arch, Obs> Relocator<T, PreH, PostH, D, Arch, Obs>
where
    Arch: RelocationArch,
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
        R: Into<ModuleHandle<Arch>>,
    {
        self.scope = ModuleScope::new(scope);
        self
    }

    /// Replaces the current module scope with a shared scope owner.
    ///
    /// Scope entries are searched in order and retained as dependencies of the
    /// relocated output.
    pub fn shared_scope(mut self, scope: ModuleScope<Arch>) -> Self {
        self.scope = scope;
        self
    }

    /// Appends more modules to the symbol-resolution scope.
    ///
    /// Additional modules are searched after the existing
    /// scope entries. Scope entries are retained as dependencies of the
    /// relocated output.
    pub fn extend_scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch>>,
    {
        self.scope = self.scope.extend(scope);
        self
    }

    /// Attaches an object and selects the user-data type carried by that object.
    pub fn with_object<U, NewD>(self, object: U) -> Relocator<U, PreH, PostH, NewD, U::Arch, Obs>
    where
        U: Relocatable<NewD>,
        Obs: RelocationObserver<U::Arch>,
    {
        Relocator {
            object,
            scope: ModuleScope::empty(),
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            observer: self.observer,
            binding: self.binding,
            _marker: PhantomData,
        }
    }

    /// Sets the relocation handler that runs before the built-in logic.
    ///
    /// This is useful for intercepting selected relocations or providing
    /// custom behavior before the default implementation runs.
    pub fn pre_handler<NewPreH>(
        self,
        handler: NewPreH,
    ) -> Relocator<T, NewPreH, PostH, D, Arch, Obs>
    where
        NewPreH: RelocationHandler<Arch>,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_handler: handler,
            post_handler: self.post_handler,
            observer: self.observer,
            binding: self.binding,
            _marker: PhantomData,
        }
    }

    /// Sets the relocation handler that runs after the built-in logic.
    ///
    /// This handler is called only if the relocation was not already handled
    /// by the pre-handler or the default relocation logic.
    pub fn post_handler<NewPostH>(
        self,
        handler: NewPostH,
    ) -> Relocator<T, PreH, NewPostH, D, Arch, Obs>
    where
        NewPostH: RelocationHandler<Arch>,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_handler: self.pre_handler,
            post_handler: handler,
            observer: self.observer,
            binding: self.binding,
            _marker: PhantomData,
        }
    }

    /// Sets the runtime-linker observer used during relocation.
    pub fn observer<NewObs>(self, observer: NewObs) -> Relocator<T, PreH, PostH, D, Arch, NewObs>
    where
        NewObs: RelocationObserver<Arch>,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            observer,
            binding: self.binding,
            _marker: PhantomData,
        }
    }

    /// Overrides the relocation binding mode.
    pub fn binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }

    #[inline]
    /// Updates the relocation binding mode in place.
    pub fn set_binding(&mut self, binding: BindingMode) {
        self.binding = binding;
    }
}

impl<T, PreH, PostH, D: 'static, Arch, Obs> Relocator<T, PreH, PostH, D, Arch, Obs>
where
    T: Relocatable<D, Arch = Arch>,
    Arch: RelocationArch,
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
    /// cross-architecture images avoid host execution of target code; attach a
    /// [`RelocationObserver`](crate::observer::RelocationObserver) that handles
    /// binding and lifecycle events when guest runtime hooks must be executed.
    pub fn relocate(self) -> Result<T::Output> {
        let Self {
            object,
            scope,
            pre_handler,
            post_handler,
            mut observer,
            binding,
            _marker,
        } = self;

        object.relocate(RelocateArgs::new(
            scope,
            binding,
            &pre_handler,
            &post_handler,
            &mut observer,
        ))
    }
}

impl<T, PreH, PostH, D: 'static, Arch, Obs> Relocator<T, PreH, PostH, D, Arch, Obs>
where
    T: SupportLazy,
    Arch: RelocationArch,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
    Obs: RelocationObserver<Arch>,
{
    /// Forces eager binding.
    pub fn eager(mut self) -> Self {
        self.binding = BindingMode::Eager;
        self
    }

    /// Forces lazy binding.
    pub fn lazy(mut self) -> Self {
        self.binding = BindingMode::Lazy;
        self
    }
}
