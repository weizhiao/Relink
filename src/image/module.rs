use super::Module;
use crate::{
    Result,
    arch::NativeArch,
    custom_error,
    relocation::RelocationArch,
    runtime::DomainId,
    sync::{Arc, AtomicUsize, Ordering, Weak, arc_unsize},
    tls::TlsResolver,
};
use alloc::vec::Vec;
use core::{any::Any, fmt, ops::Deref, slice};

const UNINITIALIZED: usize = 0;
const INITIALIZED: usize = 1;
const FINALIZED: usize = 2;

/// Lifecycle state shared by every view of one logical module.
///
/// Module implementations store this value and return it from
/// [`Module::state`]. It coordinates initialization and finalization without
/// duplicating the ownership count already maintained by [`Arc`].
pub struct ModuleState {
    value: AtomicUsize,
}

impl ModuleState {
    /// Creates state for a module whose initializer has not run.
    #[inline]
    pub const fn new() -> Self {
        Self {
            value: AtomicUsize::new(UNINITIALIZED),
        }
    }

    /// Creates state for a module that is already initialized.
    #[inline]
    pub const fn initialized() -> Self {
        Self {
            value: AtomicUsize::new(INITIALIZED),
        }
    }

    /// Returns whether the module is currently initialized.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.value.load(Ordering::Acquire) == INITIALIZED
    }

    /// Runs the module initializer at most once.
    ///
    /// The module is considered initialized once the caller wins the state
    /// transition, even if `initialize` returns an error.
    pub fn initialize(&self, initialize: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut value = self.value.load(Ordering::Acquire);
        loop {
            match value {
                INITIALIZED => return Ok(()),
                FINALIZED => return Err(custom_error("cannot initialize a finalized module")),
                _ => {}
            }
            match self.value.compare_exchange_weak(
                value,
                INITIALIZED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return initialize(),
                Err(current) => value = current,
            }
        }
    }

    /// Runs the module finalizer at most once after successful initialization.
    ///
    /// A module with finalization work should call this from its owning
    /// allocation's [`Drop`] implementation. For core-backed ELF modules,
    /// `CoreInner` already provides that integration.
    pub fn finalize(&self, finalize: impl FnOnce() -> Result<()>) -> Result<()> {
        if self
            .value
            .compare_exchange(INITIALIZED, FINALIZED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            finalize()
        } else {
            Ok(())
        }
    }
}

impl Default for ModuleState {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// One shared ownership reference to a module.
///
/// Finalization follows the lifetime of the underlying module allocation, not
/// an individual handle. Cloning or dropping a handle only changes the [`Arc`]
/// ownership count.
pub struct ModuleHandle<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    module: Arc<dyn Module<Arch, Tls>>,
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Clone for ModuleHandle<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            module: Arc::clone(&self.module),
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> ModuleHandle<Arch, Tls> {
    /// Creates the canonical shared handle for a module.
    ///
    /// Clone this handle when the same logical module is used in another scope
    /// or link context.
    #[inline]
    pub fn new<M>(module: M) -> Self
    where
        M: Module<Arch, Tls> + 'static,
    {
        Self::from_shared(arc_unsize!(Arc::new(module) => dyn Module<Arch, Tls>))
    }

    /// Wraps a shared module while preserving the state owned by that module.
    #[inline]
    pub fn from_shared(module: Arc<dyn Module<Arch, Tls>>) -> Self {
        Self { module }
    }

    /// Returns the underlying dynamic module reference.
    #[inline]
    pub fn as_dyn(&self) -> &(dyn Module<Arch, Tls> + 'static) {
        &*self.module
    }

    /// Returns whether both handles share the same logical module state.
    #[inline]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.as_dyn().state(), other.as_dyn().state())
    }

    /// Runs this module's initialization hook at most once.
    #[inline]
    pub fn initialize(&self) -> Result<()> {
        let module = self.as_dyn();
        module.state().initialize(|| module.initialize())
    }

    /// Downcasts the retained module to a concrete type.
    #[inline]
    pub fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: Module<Arch, Tls> + 'static,
    {
        let module = self.as_dyn() as &dyn Any;
        module
            .downcast_ref::<T>()
            .or_else(|| module.downcast_ref::<Arc<T>>().map(|module| &**module))
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> Deref for ModuleHandle<Arch, Tls> {
    type Target = dyn Module<Arch, Tls>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_dyn()
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> AsRef<dyn Module<Arch, Tls>>
    for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn as_ref(&self) -> &(dyn Module<Arch, Tls> + 'static) {
        self.as_dyn()
    }
}

/// Ordered, retained modules used for relocation symbol lookup.
///
/// Modules are searched in order and held alive by relocated outputs that keep
/// this scope.
pub struct ModuleScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    modules: Arc<[ModuleHandle<Arch, Tls>]>,
}

/// Weak reference to a retained module scope.
pub(crate) struct WeakModuleScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    modules: Weak<[ModuleHandle<Arch, Tls>]>,
}

/// Mutable builder for a [`ModuleScope`].
pub struct ModuleScopeBuilder<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    modules: Vec<ModuleHandle<Arch, Tls>>,
    domain: DomainId,
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Clone for ModuleScopeBuilder<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            modules: self.modules.clone(),
            domain: self.domain,
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> ModuleScopeBuilder<Arch, Tls> {
    /// Creates an empty module-scope builder for `domain`.
    #[inline]
    pub const fn new(domain: DomainId) -> Self {
        Self {
            modules: Vec::new(),
            domain,
        }
    }

    pub(crate) fn replace<I, R>(&mut self, modules: I)
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.modules.clear();
        self.modules.extend(modules.into_iter().map(Into::into));
    }

    /// Appends modules to the scope being built.
    pub fn extend<I, R>(&mut self, modules: I)
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.modules.extend(modules.into_iter().map(Into::into));
    }

    /// Finishes the builder and returns an immutable module scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the modules belong to incompatible runtime domains.
    pub fn into_scope(self) -> Result<ModuleScope<Arch, Tls>> {
        for module in &self.modules {
            self.domain.ensure(module.domain_id())?;
        }
        Ok(ModuleScope {
            modules: Arc::from(self.modules),
        })
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Clone for ModuleScope<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            modules: Arc::clone(&self.modules),
        }
    }
}

impl<Arch, Tls> fmt::Debug for ModuleScope<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.modules.iter().map(|module| module.name()))
            .finish()
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> ModuleScope<Arch, Tls> {
    pub(crate) fn ensure_domain(&self, expected: DomainId) -> Result<()> {
        match self.modules.first() {
            Some(module) => expected.ensure(module.domain_id()),
            None => Ok(()),
        }
    }

    #[inline]
    pub(crate) fn downgrade(&self) -> WeakModuleScope<Arch, Tls> {
        WeakModuleScope {
            modules: Arc::downgrade(&self.modules),
        }
    }

    /// Returns the modules in lookup order.
    #[inline]
    pub fn as_slice(&self) -> &[ModuleHandle<Arch, Tls>] {
        &self.modules
    }

    /// Iterates over modules in lookup order.
    #[inline]
    pub fn iter(&self) -> slice::Iter<'_, ModuleHandle<Arch, Tls>> {
        self.modules.iter()
    }

    /// Returns the number of modules in this scope.
    #[inline]
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Returns whether the scope contains no modules.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> WeakModuleScope<Arch, Tls> {
    #[inline]
    pub(crate) fn upgrade(&self) -> Option<ModuleScope<Arch, Tls>> {
        self.modules
            .upgrade()
            .map(|modules| ModuleScope { modules })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::SyntheticModule;

    #[test]
    fn shared_module_preserves_identity() {
        let module = Arc::new(SyntheticModule::<NativeArch>::empty("shared"));
        let first: ModuleHandle = ModuleHandle::new(module.clone());
        let second: ModuleHandle = ModuleHandle::new(module);

        assert!(first.ptr_eq(&second));
    }
}
