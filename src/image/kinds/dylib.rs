//! Dynamic library (shared object) handling
//!
//! This module provides functionality for working with dynamic libraries
//! (shared objects) that have been loaded but not yet relocated. It includes
//! support for synchronous loading of dynamic libraries.

use crate::{
    LoadHook, Loader, Result,
    elf::{ElfDyn, ElfPhdr},
    image::{ElfCore, LoadedCore, common::DynamicImage},
    input::{ElfReader, IntoElfReader},
    os::Mmap,
    parse_ehdr_error,
    relocation::{Relocatable, RelocationHandler, Relocator, SymbolLookup},
    tls::TlsResolver,
};
use alloc::vec::Vec;
use core::{borrow::Borrow, fmt::Debug, ops::Deref, ptr::NonNull};

/// An unrelocated dynamic library.
///
/// This structure represents a dynamic library (shared object, `.so`) that has been
/// loaded into memory but has not yet undergone relocation. It contains all
/// the necessary information to perform relocation and prepare the library
/// for execution.
pub struct RawDylib<D>
where
    D: 'static,
{
    /// The common part containing basic ELF object information.
    pub(crate) inner: DynamicImage<D>,
}

impl<D> Debug for RawDylib<D> {
    /// Formats the [`RawDylib`] for debugging purposes.
    ///
    /// This implementation provides a debug representation that includes
    /// the library name and its dependencies.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawDylib")
            .field("name", &self.inner.name())
            .field("needed_libs", &self.inner.needed_libs())
            .finish()
    }
}

impl<D> Relocatable<D> for RawDylib<D> {
    type Output = LoadedDylib<D>;

    fn relocate<PreS, PostS, LazyS, PreH, PostH>(
        self,
        scope: Vec<LoadedCore<D>>,
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
        lazy: Option<bool>,
        lazy_scope: Option<LazyS>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let inner = self.inner.relocate_impl(
            scope,
            pre_find,
            post_find,
            pre_handler,
            post_handler,
            lazy,
            lazy_scope,
        )?;
        Ok(LoadedDylib { inner })
    }
}

impl<D> RawDylib<D> {
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

    /// Gets the DT_RPATH value
    ///
    /// # Returns
    /// An optional string slice containing the RPATH value
    #[inline]
    pub fn rpath(&self) -> Option<&str> {
        self.inner.rpath()
    }

    /// Gets the DT_RUNPATH value
    ///
    /// # Returns
    /// An optional string slice containing the RUNPATH value
    #[inline]
    pub fn runpath(&self) -> Option<&str> {
        self.inner.runpath()
    }

    /// Gets the PT_INTERP value
    ///
    /// # Returns
    /// An optional string slice containing the interpreter path
    #[inline]
    pub fn interp(&self) -> Option<&str> {
        self.inner.interp()
    }

    /// Gets the name of the ELF object
    #[inline]
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Gets the program headers of the ELF object
    pub fn phdrs(&self) -> &[ElfPhdr] {
        self.inner.phdrs()
    }

    /// Gets the base address of the loaded ELF object
    pub fn base(&self) -> usize {
        self.inner.base()
    }

    /// Gets the total length of mapped memory for the ELF object
    pub fn mapped_len(&self) -> usize {
        self.inner.mapped_len()
    }

    /// Gets the list of needed library names from the dynamic section
    pub fn needed_libs(&self) -> &[&str] {
        self.inner.needed_libs()
    }

    /// Gets the dynamic section pointer
    ///
    /// # Returns
    /// An optional NonNull pointer to the dynamic section
    pub fn dynamic_ptr(&self) -> Option<NonNull<ElfDyn>> {
        self.inner.dynamic_ptr()
    }

    /// Gets a reference to the user data
    pub fn user_data(&self) -> &D {
        self.inner.user_data()
    }

    /// Returns a mutable reference to the user-defined data associated with this ELF object.
    ///
    /// This method provides access to the user-defined data associated
    /// with this ELF object, allowing modification of the data.
    ///
    /// # Returns
    /// * `Some(data)` - A mutable reference to the user data if available.
    /// * `None` - If the user data is not available (e.g., already borrowed).
    #[inline]
    pub fn user_data_mut(&mut self) -> Option<&mut D> {
        self.inner.user_data_mut()
    }

    /// Creates a builder for relocating the dynamic library.
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), D> {
        Relocator::new(self)
    }
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    D: Default,
    Tls: TlsResolver,
{
    /// Loads a dynamic library into memory.
    ///
    /// This method loads a dynamic library (shared object) file into memory
    /// and prepares it for relocation. The file is validated to ensure it
    /// is indeed a dynamic library.
    ///
    /// # Arguments
    /// * `object` - The ELF object to load as a dynamic library.
    ///
    /// # Returns
    /// * `Ok(RawDylib)` - The loaded dynamic library.
    /// * `Err(Error)` - If loading fails.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, input::ElfBinary};
    ///
    /// let mut loader = Loader::new();
    /// let bytes = &[]; // ELF file bytes
    /// let lib = loader.load_dylib(ElfBinary::new("liba.so", bytes)).unwrap();
    /// ```
    pub fn load_dylib<'a, I>(&mut self, input: I) -> Result<RawDylib<D>>
    where
        I: IntoElfReader<'a>,
    {
        let object = input.into_reader()?;
        self.load_dylib_impl(object)
    }

    pub(crate) fn load_dylib_impl(&mut self, mut object: impl ElfReader) -> Result<RawDylib<D>> {
        #[cfg(feature = "log")]
        log::debug!("Loading dylib: {}", object.file_name());

        // Prepare and validate the ELF header
        let ehdr = self.read_ehdr(&mut object)?;

        // Ensure the file is actually a dynamic library
        if !ehdr.is_dylib() {
            #[cfg(feature = "log")]
            log::error!(
                "[{}] Type mismatch: expected dylib, found {:?}",
                object.file_name(),
                ehdr.e_type
            );
            return Err(parse_ehdr_error("file type mismatch"));
        }

        let phdrs = self.buf.prepare_phdrs(&ehdr, &mut object)?;

        // Load the relocated common part
        let builder = self.inner.create_builder::<M, Tls>(ehdr, phdrs, object)?;
        let inner = builder.build_dynamic(phdrs)?;

        #[cfg(feature = "log")]
        log::info!(
            "Loaded dylib: {} at [0x{:x}-0x{:x}]",
            inner.name(),
            inner.base(),
            inner.base() + inner.mapped_len()
        );

        // Wrap in RawDylib and return
        Ok(RawDylib { inner })
    }
}

#[derive(Debug, Clone)]
/// A relocated dynamic library.
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
