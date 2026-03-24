//! Relocatable ELF file handling
//!
//! This module provides functionality for loading and relocating relocatable
//! ELF files (also known as object files). These are typically .o files that
//! contain code and data that need to be relocated before they can be executed.

use crate::{
    Result,
    image::{CoreInner, ElfCore, LoadedCore},
    loader::{DynLifecycleHandler, ObjectBuilder},
    relocation::{
        BindingOptions, Relocatable, RelocationHandler, Relocator, StaticRelocation, SymbolLookup,
    },
    segment::section::PltGotSection,
    sync::{Arc, AtomicBool},
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};
use core::{borrow::Borrow, fmt::Debug, ops::Deref};

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
    pub(crate) fn from_builder<T: TlsResolver>(builder: ObjectBuilder<T, D>) -> Self {
        let inner = CoreInner {
            is_init: AtomicBool::new(false),
            name: builder.name,
            symtab: builder.symtab,
            fini: None,
            fini_array: None,
            fini_handler: builder.fini_fn,
            user_data: builder.user_data,
            dynamic_info: None,
            tls_mod_id: builder.tls_mod_id,
            tls_tp_offset: builder.tls_tp_offset,
            tls_unregister: T::unregister,
            tls_desc_args: Box::new([]),
            segments: builder.segments,
        };

        Self {
            core: ElfCore {
                inner: Arc::new(inner),
            },
            pltgot: builder.pltgot,
            relocation: builder.relocation,
            mprotect: builder.mprotect,
            init_array: builder.init_array,
            init: builder.init_fn,
            tls_get_addr: T::tls_get_addr as *const () as usize,
        }
    }

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
        _binding: BindingOptions<LazyS>,
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
