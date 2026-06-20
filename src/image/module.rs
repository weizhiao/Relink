use super::Module;
use crate::{arch::NativeArch, relocation::RelocationArch, sync::Arc, tls::TlsResolver};
use alloc::{boxed::Box, vec::Vec};
use core::{any::Any, ops::Deref, slice};

/// Shared ownership handle for one retained module.
pub struct ModuleHandle<Arch: RelocationArch = NativeArch, Tls: TlsResolver = ()> {
    module: Arc<dyn Module<Arch, Tls>>,
}

impl<Arch: RelocationArch, Tls: TlsResolver> Clone for ModuleHandle<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            module: Arc::clone(&self.module),
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver + 'static> ModuleHandle<Arch, Tls> {
    /// Retains a module behind a shared trait-object handle.
    #[inline]
    pub fn new<M>(module: M) -> Self
    where
        M: Module<Arch, Tls> + 'static,
    {
        Self {
            module: Arc::from(Box::new(module) as Box<dyn Module<Arch, Tls>>),
        }
    }

    /// Wraps an existing shared module trait object.
    #[inline]
    pub fn from_shared(module: Arc<dyn Module<Arch, Tls>>) -> Self {
        Self { module }
    }

    /// Returns the underlying dynamic module reference.
    #[inline]
    pub fn as_dyn(&self) -> &(dyn Module<Arch, Tls> + 'static) {
        &*self.module
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

    /// Consumes the handle and returns the shared module trait object.
    #[inline]
    pub fn into_inner(self) -> Arc<dyn Module<Arch, Tls>> {
        self.module
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver + 'static> Deref for ModuleHandle<Arch, Tls> {
    type Target = dyn Module<Arch, Tls>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_dyn()
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver + 'static> AsRef<dyn Module<Arch, Tls>>
    for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn as_ref(&self) -> &(dyn Module<Arch, Tls> + 'static) {
        self.as_dyn()
    }
}

impl<M, Arch, Tls> From<Arc<M>> for ModuleHandle<Arch, Tls>
where
    M: Module<Arch, Tls> + 'static,
    Arch: RelocationArch,
    Tls: TlsResolver + 'static,
{
    #[inline]
    fn from(module: Arc<M>) -> Self {
        Self::new(module)
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver + 'static> From<Arc<dyn Module<Arch, Tls>>>
    for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn from(module: Arc<dyn Module<Arch, Tls>>) -> Self {
        Self::from_shared(module)
    }
}

/// Ordered, retained modules used for relocation symbol lookup.
///
/// Modules are searched in order and held alive by relocated outputs that keep
/// this scope.
pub struct ModuleScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver = ()> {
    modules: Arc<[ModuleHandle<Arch, Tls>]>,
}

/// Mutable builder for a [`ModuleScope`].
pub struct ModuleScopeBuilder<Arch: RelocationArch = NativeArch, Tls: TlsResolver = ()> {
    modules: Vec<ModuleHandle<Arch, Tls>>,
}

impl<Arch: RelocationArch, Tls: TlsResolver> Clone for ModuleScopeBuilder<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            modules: self.modules.clone(),
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver> ModuleScopeBuilder<Arch, Tls> {
    #[inline]
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
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

    pub fn extend<I, R>(&mut self, modules: I)
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.modules.extend(modules.into_iter().map(Into::into));
    }

    #[inline]
    pub fn into_scope(self) -> ModuleScope<Arch, Tls> {
        ModuleScope {
            modules: Arc::from(self.modules),
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver> Default for ModuleScopeBuilder<Arch, Tls> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver> Clone for ModuleScope<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            modules: Arc::clone(&self.modules),
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver> ModuleScope<Arch, Tls> {
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
