use crate::{
    Result,
    image::LoadedCore,
    relocation::{
        BindingMode, EmulatedArch, Emulator, HandlerHooks, LazyLookupHooks, LookupHooks,
        Relocatable, RelocateArgs, RelocationArch, RelocationHandler, SupportLazy, SymbolLookup,
    },
    sync::Arc,
};
use alloc::vec::Vec;
use core::marker::PhantomData;

fn empty_scope<D: 'static, Arch: RelocationArch>() -> Arc<[LoadedCore<D, Arch>]> {
    Arc::from(Vec::new())
}

/// A builder for configuring and executing relocation.
///
/// A relocator is obtained by calling `.relocator()` on a raw image returned by
/// [`crate::Loader`]. It lets you provide symbol lookup callbacks, dependency scope,
/// relocation handlers, and binding policy before finally calling `relocate()`.
///
/// # Examples
/// ```no_run
/// use elf_loader::{Loader, Result};
///
/// fn main() -> Result<()> {
///     let mut loader = Loader::new();
///     let lib = loader.load_dylib("path/to/liba.so")?;
///
///     let relocated = lib
///         .relocator()
///         .pre_find_fn(|name| match name {
///             "malloc" => Some(0x1234 as *const ()),
///             "free" => Some(0x5678 as *const ()),
///             _ => None,
///         })
///         .relocate()?;
///
///     let _ = relocated;
///     Ok(())
/// }
/// ```
pub struct Relocator<
    T,
    PreS,
    PostS,
    LazyPreS,
    LazyPostS,
    PreH,
    PostH,
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
> {
    object: T,
    scope: Arc<[LoadedCore<D, Arch>]>,
    pre_find: PreS,
    post_find: PostS,
    lazy_pre_find: LazyPreS,
    lazy_post_find: LazyPostS,
    pre_handler: PreH,
    post_handler: PostH,
    binding: BindingMode,
    emu: Option<Arc<dyn Emulator<Arch>>>,
    _marker: PhantomData<fn() -> (D, Arch)>,
}

impl<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D: 'static, Arch> Clone
    for Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D, Arch>
where
    Arch: RelocationArch,
    T: Clone,
    PreS: Clone,
    PostS: Clone,
    LazyPreS: Clone,
    LazyPostS: Clone,
    PreH: Clone,
    PostH: Clone,
{
    fn clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            scope: self.scope.clone(),
            pre_find: self.pre_find.clone(),
            post_find: self.post_find.clone(),
            lazy_pre_find: self.lazy_pre_find.clone(),
            lazy_post_find: self.lazy_post_find.clone(),
            pre_handler: self.pre_handler.clone(),
            post_handler: self.post_handler.clone(),
            binding: self.binding,
            emu: self.emu.clone(),
            _marker: PhantomData,
        }
    }
}

impl Relocator<(), (), (), (), (), (), (), ()> {
    /// Creates a new empty `Relocator` configuration.
    pub fn new() -> Self {
        Self {
            object: (),
            scope: empty_scope::<(), crate::arch::NativeArch>(),
            pre_find: (),
            post_find: (),
            lazy_pre_find: (),
            lazy_post_find: (),
            pre_handler: (),
            post_handler: (),
            binding: BindingMode::Default,
            emu: None,
            _marker: PhantomData,
        }
    }
}

impl<Arch: RelocationArch> Relocator<(), (), (), (), (), (), (), (), Arch> {
    /// Switches an empty relocator configuration to a different relocation backend.
    pub fn for_arch<NewArch: RelocationArch>(
        self,
    ) -> Relocator<(), (), (), (), (), (), (), (), NewArch> {
        Relocator {
            object: self.object,
            scope: empty_scope::<(), NewArch>(),
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
            emu: None,
            _marker: PhantomData,
        }
    }
}

impl<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D: 'static, Arch>
    Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D, Arch>
where
    Arch: RelocationArch,
    PreS: SymbolLookup,
    PostS: SymbolLookup,
    LazyPreS: SymbolLookup + Send + Sync + 'static,
    LazyPostS: SymbolLookup + Send + Sync + 'static,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
{
    /// Sets the preferred symbol lookup strategy.
    ///
    /// During relocation, symbols are searched here first before checking the
    /// relocation scope or any fallback lookup strategy.
    pub fn pre_find<NewPreS>(
        self,
        pre_find: NewPreS,
    ) -> Relocator<T, NewPreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D, Arch>
    where
        NewPreS: SymbolLookup,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
            emu: self.emu,
            _marker: PhantomData,
        }
    }

    /// Sets the preferred relocation-time symbol lookup using a closure.
    pub fn pre_find_fn<F>(
        self,
        pre_find: F,
    ) -> Relocator<T, F, PostS, LazyPreS, LazyPostS, PreH, PostH, D, Arch>
    where
        F: Fn(&str) -> Option<*const ()>,
    {
        self.pre_find(pre_find)
    }

    /// Sets the fallback symbol lookup strategy using a closure.
    ///
    /// During relocation, this strategy is consulted only after the preferred
    /// lookup and the current relocation scope have been exhausted.
    pub fn post_find_fn<F>(
        self,
        post_find: F,
    ) -> Relocator<T, PreS, F, LazyPreS, LazyPostS, PreH, PostH, D, Arch>
    where
        F: Fn(&str) -> Option<*const ()>,
    {
        self.post_find(post_find)
    }

    /// Sets the fallback symbol lookup strategy.
    ///
    /// During relocation, this strategy is consulted only after the preferred
    /// lookup and the current relocation scope have been exhausted.
    pub fn post_find<NewPostS>(
        self,
        post_find: NewPostS,
    ) -> Relocator<T, PreS, NewPostS, LazyPreS, LazyPostS, PreH, PostH, D, Arch>
    where
        NewPostS: SymbolLookup,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
            emu: self.emu,
            _marker: PhantomData,
        }
    }

    /// Replaces the current symbol-resolution scope.
    ///
    /// During relocation, symbols from these modules are searched in the provided order.
    /// Scope entries are retained as dependencies of the relocated output.
    pub fn scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<LoadedCore<D, Arch>>,
    {
        let scope: Vec<_> = scope.into_iter().map(Into::into).collect();
        self.scope = Arc::from(scope);
        self
    }

    /// Replaces the current symbol-resolution scope with a shared scope owner.
    ///
    /// Scope entries are searched in order and retained as dependencies of the
    /// relocated output.
    pub fn shared_scope(mut self, scope: Arc<[LoadedCore<D, Arch>]>) -> Self {
        self.scope = scope;
        self
    }

    /// Appends more modules to the symbol-resolution scope.
    ///
    /// During relocation, additional modules are searched after the existing
    /// scope entries. Scope entries are retained as dependencies of the
    /// relocated output.
    pub fn extend_scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<LoadedCore<D, Arch>>,
    {
        let mut extended = Vec::with_capacity(self.scope.len());
        extended.extend(self.scope.iter().cloned());
        extended.extend(scope.into_iter().map(Into::into));
        self.scope = Arc::from(extended);
        self
    }

    /// Attaches an object and selects the user-data type carried by that object.
    pub fn with_object<U, NewD>(
        self,
        object: U,
    ) -> Relocator<U, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, NewD, U::Arch>
    where
        U: Relocatable<NewD>,
    {
        Relocator {
            object,
            scope: empty_scope::<NewD, U::Arch>(),
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
            emu: None,
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
    ) -> Relocator<T, PreS, PostS, LazyPreS, LazyPostS, NewPreH, PostH, D, Arch>
    where
        NewPreH: RelocationHandler<Arch>,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: handler,
            post_handler: self.post_handler,
            binding: self.binding,
            emu: self.emu,
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
    ) -> Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, NewPostH, D, Arch>
    where
        NewPostH: RelocationHandler<Arch>,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: handler,
            binding: self.binding,
            emu: self.emu,
            _marker: PhantomData,
        }
    }

    /// Overrides the relocation binding mode.
    pub fn binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }

    #[inline]
    pub fn set_binding(&mut self, binding: BindingMode) {
        self.binding = binding;
    }
}

impl<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D: 'static, Arch>
    Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D, Arch>
where
    Arch: EmulatedArch,
{
    /// Sets the emulator used for non-native runtime hooks.
    ///
    /// This method is available only for non-native architecture backends.
    pub fn emulator<E>(mut self, emu: E) -> Self
    where
        E: Emulator<Arch>,
    {
        self.emu = Some(Arc::new(emu));
        self
    }

    /// Alias for [`Relocator::emulator`].
    #[inline]
    pub fn emu<E>(self, emu: E) -> Self
    where
        E: Emulator<Arch>,
    {
        self.emulator(emu)
    }
}

impl<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D: 'static, Arch>
    Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D, Arch>
where
    T: Relocatable<D, Arch = Arch>,
    Arch: RelocationArch,
    PreS: SymbolLookup,
    PostS: SymbolLookup,
    LazyPreS: SymbolLookup + Send + Sync + 'static,
    LazyPostS: SymbolLookup + Send + Sync + 'static,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
{
    /// Executes relocation with the current configuration.
    ///
    /// This consumes the builder, resolves relocations, retains the configured
    /// relocation scope as dependencies, and returns the final loaded image.
    ///
    /// The relocation backend is selected automatically from the relocated
    /// object's [`Relocatable::Arch`]: native images use
    /// [`crate::arch::NativeArch`] (the default) and run target init arrays,
    /// IFUNC resolvers,
    /// lazy-binding trampolines, and TLS resolver stubs as usual;
    /// cross-architecture images carry their own backend with
    /// `SUPPORTS_NATIVE_RUNTIME == false`; attach an
    /// [`Emulator`](crate::relocation::Emulator) when guest runtime hooks such
    /// as IFUNC, TLSDESC, and lifecycle callbacks must be executed.
    pub fn relocate(self) -> Result<T::Output> {
        let Self {
            object,
            scope,
            pre_find,
            post_find,
            lazy_pre_find,
            lazy_post_find,
            pre_handler,
            post_handler,
            binding,
            emu,
            _marker,
        } = self;

        object.relocate(RelocateArgs::new(
            scope,
            binding,
            LookupHooks::new(&pre_find, &post_find),
            LazyLookupHooks::new(lazy_pre_find, lazy_post_find),
            HandlerHooks::new(&pre_handler, &post_handler),
            emu,
        ))
    }
}

impl<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D: 'static, Arch>
    Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D, Arch>
where
    T: SupportLazy,
    Arch: RelocationArch,
    PreS: SymbolLookup,
    PostS: SymbolLookup,
    LazyPreS: SymbolLookup + Send + Sync + 'static,
    LazyPostS: SymbolLookup + Send + Sync + 'static,
    PreH: RelocationHandler<Arch>,
    PostH: RelocationHandler<Arch>,
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

    /// Sets the preferred symbol lookup used during lazy binding fixups.
    pub fn lazy_pre_find<NewLazyPreS>(
        self,
        lazy_pre_find: NewLazyPreS,
    ) -> Relocator<T, PreS, PostS, NewLazyPreS, LazyPostS, PreH, PostH, D, Arch>
    where
        NewLazyPreS: SymbolLookup + Send + Sync + 'static,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
            emu: self.emu,
            _marker: PhantomData,
        }
    }

    /// Sets the preferred lazy-binding lookup using a closure.
    pub fn lazy_pre_find_fn<F>(
        self,
        lazy_pre_find: F,
    ) -> Relocator<T, PreS, PostS, F, LazyPostS, PreH, PostH, D, Arch>
    where
        F: Fn(&str) -> Option<*const ()> + Send + Sync + 'static,
    {
        self.lazy_pre_find(lazy_pre_find)
    }

    /// Sets the fallback symbol lookup used during lazy binding fixups.
    pub fn lazy_post_find<NewLazyPostS>(
        self,
        lazy_post_find: NewLazyPostS,
    ) -> Relocator<T, PreS, PostS, LazyPreS, NewLazyPostS, PreH, PostH, D, Arch>
    where
        NewLazyPostS: SymbolLookup + Send + Sync + 'static,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
            emu: self.emu,
            _marker: PhantomData,
        }
    }

    /// Sets the fallback lazy-binding lookup using a closure.
    pub fn lazy_post_find_fn<F>(
        self,
        lazy_post_find: F,
    ) -> Relocator<T, PreS, PostS, LazyPreS, F, PreH, PostH, D, Arch>
    where
        F: Fn(&str) -> Option<*const ()> + Send + Sync + 'static,
    {
        self.lazy_post_find(lazy_post_find)
    }

    /// Reuses relocate-time symbol lookups for lazy binding fixups.
    pub fn share_find_with_lazy(
        self,
    ) -> Relocator<T, PreS, PostS, PreS, PostS, PreH, PostH, D, Arch>
    where
        PreS: Clone + Send + Sync + 'static,
        PostS: Clone + Send + Sync + 'static,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find.clone(),
            post_find: self.post_find.clone(),
            lazy_pre_find: self.pre_find,
            lazy_post_find: self.post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
            emu: self.emu,
            _marker: PhantomData,
        }
    }
}
