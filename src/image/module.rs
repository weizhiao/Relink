use super::{LoadedCore, Module};
use crate::{arch::NativeArch, memory::RegionAccess, relocation::RelocationArch, sync::Arc};
use alloc::{boxed::Box, vec::Vec};
use core::{ops::Deref, slice};

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
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.as_any().downcast_ref()
    }

    /// Downcasts the retained module to a loaded ELF image.
    #[inline]
    pub fn as_loaded<D, R>(&self) -> Option<&LoadedCore<D, Arch, R>>
    where
        D: 'static,
        R: RegionAccess,
    {
        self.downcast_ref()
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

impl<Arch: RelocationArch> Clone for ModuleScope<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            modules: Arc::clone(&self.modules),
        }
    }
}

impl<Arch: RelocationArch> ModuleScope<Arch> {
    /// Returns an empty lookup scope.
    #[inline]
    pub fn empty() -> Self {
        Self {
            modules: Arc::from(Vec::<ModuleHandle<Arch>>::new()),
        }
    }

    /// Builds a lookup scope from an ordered sequence of modules.
    pub fn new<I, R>(modules: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch>>,
    {
        Self {
            modules: Arc::from(modules.into_iter().map(Into::into).collect::<Vec<_>>()),
        }
    }

    /// Wraps an existing shared module slice.
    #[inline]
    pub fn from_shared(modules: Arc<[ModuleHandle<Arch>]>) -> Self {
        Self { modules }
    }

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

    /// Returns a new scope with additional modules appended after existing ones.
    pub fn extend<I, R>(&self, modules: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch>>,
    {
        let modules = modules.into_iter();
        let additional = modules.size_hint().0;
        let mut extended = Vec::with_capacity(self.modules.len().saturating_add(additional));
        extended.extend(self.modules.iter().cloned());
        extended.extend(modules.map(Into::into));
        Self {
            modules: Arc::from(extended),
        }
    }
}

impl<Arch: RelocationArch> From<Arc<[ModuleHandle<Arch>]>> for ModuleScope<Arch> {
    #[inline]
    fn from(modules: Arc<[ModuleHandle<Arch>]>) -> Self {
        Self::from_shared(modules)
    }
}

impl<Arch: RelocationArch> From<Vec<ModuleHandle<Arch>>> for ModuleScope<Arch> {
    #[inline]
    fn from(modules: Vec<ModuleHandle<Arch>>) -> Self {
        Self {
            modules: Arc::from(modules),
        }
    }
}
