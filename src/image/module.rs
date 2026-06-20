use super::Module;
use crate::{arch::NativeArch, relocation::RelocationArch, sync::Arc};
use alloc::{boxed::Box, vec::Vec};
use core::{any::Any, ops::Deref, slice};

/// Shared ownership handle for one retained module.
pub struct ModuleHandle<Arch: RelocationArch = NativeArch> {
    module: Arc<dyn Module<Arch>>,
}

impl<Arch: RelocationArch> Clone for ModuleHandle<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            module: Arc::clone(&self.module),
        }
    }
}

impl<Arch: RelocationArch> ModuleHandle<Arch> {
    /// Retains a module behind a shared trait-object handle.
    #[inline]
    pub fn new<M>(module: M) -> Self
    where
        M: Module<Arch> + 'static,
    {
        Self {
            module: Arc::from(Box::new(module) as Box<dyn Module<Arch>>),
        }
    }

    /// Wraps an existing shared module trait object.
    #[inline]
    pub fn from_shared(module: Arc<dyn Module<Arch>>) -> Self {
        Self { module }
    }

    /// Returns the underlying dynamic module reference.
    #[inline]
    pub fn as_dyn(&self) -> &(dyn Module<Arch> + 'static) {
        &*self.module
    }

    /// Downcasts the retained module to a concrete type.
    #[inline]
    pub fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: Module<Arch> + 'static,
    {
        let module = self.as_dyn() as &dyn Any;
        module
            .downcast_ref::<T>()
            .or_else(|| module.downcast_ref::<Arc<T>>().map(|module| &**module))
    }

    /// Consumes the handle and returns the shared module trait object.
    #[inline]
    pub fn into_inner(self) -> Arc<dyn Module<Arch>> {
        self.module
    }
}

impl<Arch: RelocationArch> Deref for ModuleHandle<Arch> {
    type Target = dyn Module<Arch>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_dyn()
    }
}

impl<Arch: RelocationArch> AsRef<dyn Module<Arch>> for ModuleHandle<Arch> {
    #[inline]
    fn as_ref(&self) -> &(dyn Module<Arch> + 'static) {
        self.as_dyn()
    }
}

impl<M, Arch> From<Arc<M>> for ModuleHandle<Arch>
where
    M: Module<Arch> + 'static,
    Arch: RelocationArch,
{
    #[inline]
    fn from(module: Arc<M>) -> Self {
        Self::new(module)
    }
}

impl<Arch: RelocationArch> From<Arc<dyn Module<Arch>>> for ModuleHandle<Arch> {
    #[inline]
    fn from(module: Arc<dyn Module<Arch>>) -> Self {
        Self::from_shared(module)
    }
}

/// Ordered, retained modules used for relocation symbol lookup.
///
/// Modules are searched in order and held alive by relocated outputs that keep
/// this scope.
pub struct ModuleScope<Arch: RelocationArch = NativeArch> {
    modules: Arc<[ModuleHandle<Arch>]>,
}

/// Mutable builder for a [`ModuleScope`].
pub struct ModuleScopeBuilder<Arch: RelocationArch = NativeArch> {
    modules: Vec<ModuleHandle<Arch>>,
}

impl<Arch: RelocationArch> Clone for ModuleScopeBuilder<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            modules: self.modules.clone(),
        }
    }
}

impl<Arch: RelocationArch> ModuleScopeBuilder<Arch> {
    #[inline]
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    pub(crate) fn replace<I, R>(&mut self, modules: I)
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch>>,
    {
        self.modules.clear();
        self.modules.extend(modules.into_iter().map(Into::into));
    }

    pub fn extend<I, R>(&mut self, modules: I)
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch>>,
    {
        self.modules.extend(modules.into_iter().map(Into::into));
    }

    #[inline]
    pub fn into_scope(self) -> ModuleScope<Arch> {
        ModuleScope {
            modules: Arc::from(self.modules),
        }
    }
}

impl<Arch: RelocationArch> Default for ModuleScopeBuilder<Arch> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<Arch: RelocationArch> Clone for ModuleScope<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            modules: Arc::clone(&self.modules),
        }
    }
}

impl<Arch: RelocationArch> ModuleScope<Arch> {
    /// Returns the modules in lookup order.
    #[inline]
    pub fn as_slice(&self) -> &[ModuleHandle<Arch>] {
        &self.modules
    }

    /// Iterates over modules in lookup order.
    #[inline]
    pub fn iter(&self) -> slice::Iter<'_, ModuleHandle<Arch>> {
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
