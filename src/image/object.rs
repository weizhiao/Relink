//! Relocatable ELF file handling
//!
//! This module provides functionality for loading and relocating relocatable
//! ELF files (also known as object files). These are typically `.o` files that
//! contain code and data that need to be relocated before they can be executed.

use crate::object::{ObjectBuilder, ObjectRelocation, PltGotSection};
use crate::{
    RelocationError, Result,
    loader::DynLifecycleHandler,
    relocation::{
        NativeRelocationArch, RelocAddr, Relocatable, RelocateArgs, RelocationArch,
        RelocationHandler, Relocator, SymbolLookup,
    },
    sync::{Arc, AtomicBool},
    tls::{CoreTlsState, TlsResolver},
};
use alloc::boxed::Box;
use core::{borrow::Borrow, fmt::Debug, ops::Deref};

use super::{CoreInner, ElfCore, LoadedCore};

/// A relocatable ELF object.
///
/// This structure represents a relocatable ELF file (typically a `.o` file)
/// that has been loaded into memory and is ready for relocation. It contains
/// all the necessary information to perform the relocation process.
pub struct RawObject<D = ()> {
    /// Core component containing basic ELF information.
    pub(crate) core: ElfCore<D>,

    /// Object relocation information.
    pub(crate) relocation: ObjectRelocation,

    /// PLT/GOT section information.
    pub(crate) pltgot: PltGotSection,

    /// Memory protection function.
    pub(crate) mprotect: Box<dyn Fn() -> Result<()>>,

    /// Initialization function handler.
    pub(crate) init: DynLifecycleHandler,

    /// Initialization function array.
    pub(crate) init_array: Option<&'static [fn()]>,
}

impl<D> Deref for RawObject<D> {
    type Target = ElfCore<D>;

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
            tls: CoreTlsState::new(
                builder.tls_mod_id,
                builder.tls_tp_offset,
                RelocAddr::from_ptr(T::tls_get_addr as *const ()),
                T::unregister,
            ),
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
        }
    }

    /// Creates a builder for relocating the relocatable file.
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), (), D> {
        Relocator::new().with_object(self)
    }
}

impl<D> Debug for RawObject<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawObject")
            .field("core", &self.core)
            .finish()
    }
}

impl<D: 'static> Relocatable<D> for RawObject<D> {
    type Output = LoadedObject<D>;

    fn relocate<A, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>,
    ) -> Result<Self::Output>
    where
        A: RelocationArch,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyPreS: SymbolLookup + Send + Sync + 'static,
        LazyPostS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        if A::MACHINE != NativeRelocationArch::MACHINE {
            return Err(RelocationError::UnsupportedRelocationType.into());
        }

        let RelocateArgs {
            scope,
            lookup,
            handlers,
            ..
        } = args;
        let inner = self.link_impl(
            &scope,
            lookup.pre_find,
            lookup.post_find,
            handlers.pre,
            handlers.post,
        )?;
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
