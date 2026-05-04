//! Shared-object image types.
//!
//! Use [`RawDylib`] for a mapped-but-unrelocated shared object. Relocation returns
//! the common [`LoadedCore`] representation.

use crate::{
    Result,
    elf::{ElfDyn, ElfPhdr},
    image::{ElfCore, LoadedCore, RawDynamic},
    relocation::{Relocatable, RelocateArgs, RelocationHandler, Relocator, SymbolLookup},
};
use core::{fmt::Debug, ptr::NonNull};

/// A mapped but unrelocated shared object.
///
/// Values of this type are returned by [`crate::Loader::load_dylib`]. They expose
/// ELF metadata immediately and can later be turned into a [`LoadedCore`] by running
/// relocation.
pub struct RawDylib<D>
where
    D: 'static,
{
    /// The common part containing basic ELF object information.
    pub(crate) inner: RawDynamic<D>,
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
    type Output = LoadedCore<D>;

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
        Relocatable::relocate(self.inner, args)
    }
}

#[cfg(feature = "lazy-binding")]
impl<D> crate::relocation::SupportLazy for RawDylib<D> {}

impl<D> RawDylib<D> {
    /// Creates a new `RawDylib` from a `RawDynamic`.
    #[inline]
    pub fn from_dynamic(inner: RawDynamic<D>) -> Self {
        Self { inner }
    }

    /// Converts this `RawDylib` into a `RawDynamic`.
    #[inline]
    pub fn into_dynamic(self) -> RawDynamic<D> {
        self.inner
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

    pub fn tls_mod_id(&self) -> Option<usize> {
        self.inner.tls_mod_id()
    }

    pub fn tls_tp_offset(&self) -> Option<isize> {
        self.inner.tls_tp_offset()
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

    /// Returns the length of the bounding runtime span covered by mapped slices.
    pub fn mapped_len(&self) -> usize {
        self.inner.mapped_len()
    }

    /// Returns the lowest runtime address covered by this object's mapped slices.
    pub(crate) fn mapped_base(&self) -> usize {
        self.inner.mapped_base()
    }

    /// Returns whether `addr` is inside one of this object's mapped slices.
    pub fn contains_addr(&self, addr: usize) -> bool {
        self.inner.contains_addr(addr)
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
        Relocator::new().with_object(self)
    }
}
