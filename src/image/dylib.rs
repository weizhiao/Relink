//! Shared-object image types.
//!
//! Use [`RawDylib`] for a mapped-but-unrelocated shared object and [`LoadedDylib`]
//! for the relocated form returned by `.relocator().relocate()`.

use crate::{
    elf::{ElfDyn, ElfPhdr},
    image::{DynamicImage, ElfCore, LoadedCore},
    loader::{ImageBuilder, LoadHook},
    os::Mmap,
    relocation::{Relocatable, RelocateArgs, RelocationHandler, Relocator, SymbolLookup},
    tls::TlsResolver,
    Result,
};
use core::{borrow::Borrow, fmt::Debug, ops::Deref, ptr::NonNull};

/// A mapped but unrelocated shared object.
///
/// Values of this type are returned by [`crate::Loader::load_dylib`]. They expose
/// ELF metadata immediately and can later be turned into a [`LoadedDylib`] by
/// running relocation.
pub struct RawDylib<D>
where
    D: 'static,
{
    /// The common part containing basic ELF object information.
    pub(crate) inner: DynamicImage<D>,
}

impl<D> Debug for RawDylib<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawDylib")
            .field("name", &self.inner.name())
            .field("needed_libs", &self.inner.needed_libs())
            .finish()
    }
}

impl<D> Relocatable<D> for RawDylib<D> {
    type Output = LoadedDylib<D>;

    fn relocate<PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyPreS: SymbolLookup + Send + Sync + 'static,
        LazyPostS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let inner = self.inner.relocate_impl(args)?;
        Ok(LoadedDylib { inner })
    }
}

#[cfg(feature = "lazy-binding")]
impl<D> crate::relocation::SupportLazy for RawDylib<D> {}

impl<D> RawDylib<D> {
    pub(crate) fn from_builder<'hook, H, M, Tls>(
        builder: ImageBuilder<'hook, H, M, Tls, D>,
        phdrs: &[ElfPhdr],
    ) -> Result<Self>
    where
        H: LoadHook,
        M: Mmap,
        Tls: TlsResolver,
    {
        Ok(Self {
            inner: DynamicImage::from_builder(builder, phdrs)?,
        })
    }

    /// Gets the entry point of the ELF object.
    #[inline]
    pub fn entry(&self) -> usize {
        self.inner.entry()
    }

    /// Gets the core component reference of the ELF object.
    #[inline]
    pub fn core_ref(&self) -> &ElfCore<D> {
        self.inner.core_ref()
    }

    /// Gets the core component of the ELF object.
    #[inline]
    pub fn core(&self) -> ElfCore<D> {
        self.inner.core()
    }

    /// Converts this object into its core component.
    #[inline]
    pub fn into_core(self) -> ElfCore<D> {
        self.inner.into_core()
    }

    /// Whether lazy binding is enabled for the current ELF object
    #[inline]
    pub fn is_lazy(&self) -> bool {
        self.inner.is_lazy()
    }

    /// Returns the DT_RPATH value.
    #[inline]
    pub fn rpath(&self) -> Option<&str> {
        self.inner.rpath()
    }

    /// Returns the DT_RUNPATH value.
    #[inline]
    pub fn runpath(&self) -> Option<&str> {
        self.inner.runpath()
    }

    /// Returns the PT_INTERP value.
    #[inline]
    pub fn interp(&self) -> Option<&str> {
        self.inner.interp()
    }

    /// Returns the name of the ELF object.
    #[inline]
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Returns the short name of the ELF object.
    #[inline]
    pub fn short_name(&self) -> &str {
        self.inner.core_ref().short_name()
    }

    /// Returns the program headers of the ELF object.
    pub fn phdrs(&self) -> &[ElfPhdr] {
        self.inner.phdrs()
    }

    /// Returns the base address of the loaded ELF object.
    pub fn base(&self) -> usize {
        self.inner.base()
    }

    /// Returns the total length of mapped memory for the ELF object.
    pub fn mapped_len(&self) -> usize {
        self.inner.mapped_len()
    }

    /// Returns the list of needed library names from the dynamic section.
    pub fn needed_libs(&self) -> &[&str] {
        self.inner.needed_libs()
    }

    /// Returns the dynamic section pointer.
    pub fn dynamic_ptr(&self) -> Option<NonNull<ElfDyn>> {
        self.inner.dynamic_ptr()
    }

    /// Returns a reference to the user data.
    pub fn user_data(&self) -> &D {
        self.inner.user_data()
    }

    /// Returns a mutable reference to the user data.
    #[inline]
    pub fn user_data_mut(&mut self) -> Option<&mut D> {
        self.inner.user_data_mut()
    }

    /// Creates a relocation builder for this shared object.
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), (), D> {
        Relocator::new(self)
    }
}

/// A relocated dynamic library.
///
/// This is a thin wrapper around [`LoadedCore`] and dereferences to it for
/// convenient access to common loaded-image operations.
#[derive(Debug, Clone)]
pub struct LoadedDylib<D> {
    inner: LoadedCore<D>,
}

impl<D> Deref for LoadedDylib<D> {
    type Target = LoadedCore<D>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D> Borrow<LoadedCore<D>> for LoadedDylib<D> {
    fn borrow(&self) -> &LoadedCore<D> {
        &self.inner
    }
}

impl<D> Borrow<LoadedCore<D>> for &LoadedDylib<D> {
    fn borrow(&self) -> &LoadedCore<D> {
        &self.inner
    }
}
