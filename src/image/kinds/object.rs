//! Relocatable ELF file handling
//!
//! This module provides functionality for loading and relocating relocatable
//! ELF files (also known as object files). These are typically .o files that
//! contain code and data that need to be relocated before they can be executed.

use crate::{
    Loader, Result,
    image::{ElfCore, LoadedCore, builder::ObjectBuilder, common::CoreInner},
    input::{ElfReader, IntoElfReader},
    loader::{DynLifecycleHandler, LoadHook},
    os::Mmap,
    relocation::{Relocatable, RelocationHandler, Relocator, StaticRelocation, SymbolLookup},
    segment::section::PltGotSection,
    sync::{Arc, AtomicBool},
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};
use core::{borrow::Borrow, fmt::Debug, ops::Deref};

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    D: Default + 'static,
    Tls: TlsResolver,
{
    /// Loads a object ELF file into memory.
    ///
    /// This method loads a relocatable ELF file (typically a `.o` file) into memory
    /// and prepares it for relocation. The file is not yet relocated after this
    /// operation.
    ///
    /// # Arguments
    /// * `object` - The ELF object to load.
    ///
    /// # Returns
    /// * `Ok(RawObject)` - The loaded relocatable ELF file.
    /// * `Err(Error)` - If loading fails.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, input::ElfBinary};
    ///
    /// let mut loader = Loader::new();
    /// let bytes = &[]; // Relocatable ELF bytes
    /// let rel = loader.load_object(ElfBinary::new("liba.o", bytes)).unwrap();
    /// ```
    pub fn load_object<'a, I>(&mut self, input: I) -> Result<RawObject<D>>
    where
        I: IntoElfReader<'a>,
    {
        let object = input.into_reader()?;
        self.load_object_impl(object)
    }

    pub(crate) fn load_object_impl(&mut self, mut object: impl ElfReader) -> Result<RawObject<D>> {
        #[cfg(feature = "log")]
        log::debug!("Loading object: {}", object.file_name());

        let ehdr = self.buf.prepare_ehdr(&mut object)?;
        let shdrs = self.buf.prepare_shdrs_mut(&ehdr, &mut object)?;
        let builder = self
            .inner
            .create_object_builder::<M, Tls>(ehdr, shdrs, object)?;
        let raw = builder.build();

        #[cfg(feature = "log")]
        log::info!(
            "Loaded object: {} at [0x{:x}-0x{:x}]",
            raw.name(),
            raw.base(),
            raw.base() + raw.core.inner.segments.len()
        );

        Ok(raw)
    }
}

impl<Tls: TlsResolver, D> ObjectBuilder<Tls, D> {
    /// Build the final RawObject
    ///
    /// This method constructs the final RawObject from the
    /// components collected during the building process.
    ///
    /// # Returns
    /// A RawObject instance ready for relocation
    pub(crate) fn build(self) -> RawObject<D> {
        // Create the inner component structure
        let inner = CoreInner {
            is_init: AtomicBool::new(false),
            name: self.name,
            symtab: self.symtab,
            fini: None,
            fini_array: None,
            fini_handler: self.fini_fn,
            user_data: self.user_data,
            dynamic_info: None,
            tls_mod_id: self.tls_mod_id,
            tls_tp_offset: self.tls_tp_offset,
            tls_unregister: Tls::unregister,
            tls_desc_args: Box::new([]),
            segments: self.segments,
        };

        // Construct and return the ElfRelocatable object
        RawObject {
            core: ElfCore {
                inner: Arc::new(inner),
            },
            pltgot: self.pltgot,
            relocation: self.relocation,
            mprotect: self.mprotect,
            init_array: self.init_array,
            init: self.init_fn,
            tls_get_addr: Tls::tls_get_addr as *const () as usize,
        }
    }
}

/// A relocatable ELF object.
///
/// This structure represents a relocatable ELF file (typically a `.o` file)
/// that has been loaded into memory and is ready for relocation. It contains
/// all the necessary information to perform the relocation process.
pub struct RawObject<D = ()> {
    /// Core component containing basic ELF information.
    pub(crate) core: ElfCore<D>,

    /// Static relocation information.
    pub(crate) relocation: StaticRelocation,

    /// PLT/GOT section information.
    pub(crate) pltgot: PltGotSection,

    /// Memory protection function.
    pub(crate) mprotect: Box<dyn Fn() -> Result<()>>,

    /// Initialization function handler.
    pub(crate) init: DynLifecycleHandler,

    /// Initialization function array.
    pub(crate) init_array: Option<&'static [fn()]>,

    /// TLS function address for __tls_get_addr.
    pub(crate) tls_get_addr: usize,
}

impl<D> Deref for RawObject<D> {
    type Target = ElfCore<D>;

    /// Dereferences to the underlying [`ElfCore`].
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<D: 'static> RawObject<D> {
    /// Creates a builder for relocating the relocatable file.
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), D> {
        Relocator::new(self)
    }
}

impl<D> Debug for RawObject<D> {
    /// Formats the [`RawObject`] for debugging purposes.
    ///
    /// This implementation provides a debug representation that includes
    /// the object name.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawObject")
            .field("core", &self.core)
            .finish()
    }
}

impl<D: 'static> Relocatable<D> for RawObject<D> {
    type Output = LoadedObject<D>;

    fn relocate<PreS, PostS, LazyS, PreH, PostH>(
        self,
        scope: Vec<LoadedCore<D>>,
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
        _lazy: Option<bool>,
        _lazy_scope: Option<LazyS>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let inner = self.relocate_impl(&scope, pre_find, post_find, pre_handler, post_handler)?;
        Ok(LoadedObject { inner })
    }
}

/// A relocated object file.
#[derive(Debug, Clone)]
pub struct LoadedObject<D> {
    pub(crate) inner: LoadedCore<D>,
}

impl<D> Deref for LoadedObject<D> {
    type Target = LoadedCore<D>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D> Borrow<LoadedCore<D>> for LoadedObject<D> {
    fn borrow(&self) -> &LoadedCore<D> {
        &self.inner
    }
}

impl<D> Borrow<LoadedCore<D>> for &LoadedObject<D> {
    fn borrow(&self) -> &LoadedCore<D> {
        &self.inner
    }
}
