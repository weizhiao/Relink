//! Relocatable ELF file handling
//!
//! This module provides functionality for loading and relocating relocatable
//! ELF files (also known as object files). These are typically `.o` files that
//! contain code and data that need to be relocated before they can be executed.

use crate::object::{ObjectBuilder, ObjectRelocation, PltGotSection};
use crate::{
    Result,
    loader::DynLifecycleHandler,
    relocation::{
        RelocAddr, Relocatable, RelocateArgs, RelocationArch, RelocationHandler, Relocator,
        SymbolLookup,
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
pub struct RawObject<D: 'static = (), Arch: RelocationArch = crate::arch::NativeArch> {
    /// Core component containing basic ELF information.
    pub(crate) core: ElfCore<D, Arch>,

    /// Object relocation information.
    pub(crate) relocation: ObjectRelocation<Arch>,

    /// PLT/GOT section information.
    pub(crate) pltgot: PltGotSection,

    /// Memory protection function.
    pub(crate) mprotect: Box<dyn Fn() -> Result<()>>,

    /// Initialization function handler.
    pub(crate) init: DynLifecycleHandler,

    /// Initialization function array.
    pub(crate) init_array: Option<&'static [fn()]>,
}

impl<D: 'static, Arch: RelocationArch> Deref for RawObject<D, Arch> {
    type Target = ElfCore<D, Arch>;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<D: 'static, Arch: RelocationArch> RawObject<D, Arch> {
    pub(crate) fn from_builder<T: TlsResolver>(builder: ObjectBuilder<T, D, Arch>) -> Self {
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
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), (), D, Arch>
    where
        Self: Relocatable<D, Arch = Arch>,
    {
        Relocator::new().with_object(self)
    }
}

impl<D: 'static, Arch: RelocationArch> Debug for RawObject<D, Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawObject")
            .field("core", &self.core)
            .finish()
    }
}

impl<D: 'static, Arch> Relocatable<D> for RawObject<D, Arch>
where
    Arch: RelocationArch,
{
    type Output = LoadedObject<D, Arch>;
    type Arch = Arch;

    fn relocate<PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, Arch, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyPreS: SymbolLookup + Send + Sync + 'static,
        LazyPostS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
    {
        let RelocateArgs {
            scope,
            lookup,
            handlers,
            ..
        } = args;
        let inner = self.relocate_impl(
            scope,
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
pub struct LoadedObject<D: 'static, Arch: RelocationArch = crate::arch::NativeArch> {
    pub(crate) inner: LoadedCore<D, Arch>,
}

impl<D: 'static, Arch: RelocationArch> Deref for LoadedObject<D, Arch> {
    type Target = LoadedCore<D, Arch>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch> Borrow<LoadedCore<D, Arch>> for LoadedObject<D, Arch> {
    fn borrow(&self) -> &LoadedCore<D, Arch> {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch> Borrow<LoadedCore<D, Arch>> for &LoadedObject<D, Arch> {
    fn borrow(&self) -> &LoadedCore<D, Arch> {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch> From<LoadedObject<D, Arch>> for LoadedCore<D, Arch> {
    #[inline]
    fn from(object: LoadedObject<D, Arch>) -> Self {
        object.inner
    }
}

impl<D: 'static, Arch: RelocationArch> From<&LoadedObject<D, Arch>> for LoadedCore<D, Arch> {
    #[inline]
    fn from(object: &LoadedObject<D, Arch>) -> Self {
        object.inner.clone()
    }
}
