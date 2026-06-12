//! Relocatable ELF file handling
//!
//! This module provides functionality for loading and relocating relocatable
//! ELF files (also known as object files). These are typically `.o` files that
//! contain code and data that need to be relocated before they can be executed.

use crate::object::{CustomHash, ObjectBuilder, PltGotSection};
use crate::segment::ElfSegments;
use crate::{
    Result,
    elf::{ElfShdr, Lifecycle, SymbolTable},
    memory::{HostRegion, RegionAccess, VmAddr},
    observer::RelocationObserver,
    relocation::{
        ObjectRelocationArch, Relocatable, RelocateArgs, RelocationArch, RelocationHandler,
        Relocator,
    },
    sync::{Arc, AtomicBool},
    tls::{CoreTlsState, TlsResolver},
};
use alloc::{boxed::Box, vec::Vec};
use core::{borrow::Borrow, cell::OnceCell, fmt::Debug, ops::Deref};

use super::{CoreInner, ElfCore, LoadedCore, ModuleHandle};

/// A relocatable ELF object.
///
/// This structure represents a relocatable ELF file (typically a `.o` file)
/// that has been loaded into memory and is ready for relocation. It contains
/// all the necessary information to perform the relocation process.
pub struct RawObject<
    D: 'static = (),
    Arch: ObjectRelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    /// Core component containing basic ELF information.
    pub(crate) core: ElfCore<D, Arch, R, CustomHash>,

    /// Rebased section headers retained for object relocation metadata.
    pub(crate) shdrs: Vec<ElfShdr<Arch::Layout>>,

    /// PLT/GOT section information.
    pub(crate) pltgot: PltGotSection,

    /// Memory protection function.
    pub(crate) mprotect:
        Box<dyn for<'segments> Fn(&crate::object::ObjectSegmentView<'segments, R>) -> Result<()>>,

    /// Initialization-only mapped memory.
    pub(crate) init_segments: Option<ElfSegments<R>>,

    /// Symbol table to install after initialization memory can be released.
    pub(crate) post_init_symtab: Option<SymbolTable<Arch::Layout, CustomHash>>,

    /// Initialization lifecycle.
    pub(crate) init: Lifecycle,
}

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess> Deref for RawObject<D, Arch, R> {
    type Target = ElfCore<D, Arch, R, CustomHash>;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess> RawObject<D, Arch, R> {
    pub(crate) fn from_builder<T: TlsResolver>(builder: ObjectBuilder<T, D, Arch, R>) -> Self {
        let (segments, init_segments) = builder.segments.into_parts();
        let inner = CoreInner {
            is_init: AtomicBool::new(false),
            path: builder.path,
            symtab: builder.symtab,
            finalizer: OnceCell::new(),
            user_data: builder.user_data,
            dynamic_info: None,
            tls: CoreTlsState::new(
                builder.tls_mod_id,
                builder.tls_tp_offset,
                VmAddr::from_ptr(T::tls_get_addr as *const ()),
                T::unregister,
            ),
            segments,
        };

        Self {
            core: ElfCore {
                inner: Arc::new(inner),
            },
            shdrs: builder.shdrs,
            pltgot: builder.pltgot,
            mprotect: builder.mprotect,
            init_segments,
            post_init_symtab: builder.post_init_symtab,
            init: builder.init,
        }
    }

    /// Creates a builder for relocating the relocatable file.
    pub fn relocator(self) -> Relocator<Self, (), (), Arch>
    where
        Self: Relocatable<D, Arch = Arch>,
    {
        Relocator::<(), (), (), Arch>::new().with_object(self)
    }
}

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess> Debug for RawObject<D, Arch, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawObject")
            .field("core", &self.core)
            .finish()
    }
}

impl<D: 'static, Arch, R> Relocatable<D> for RawObject<D, Arch, R>
where
    Arch: ObjectRelocationArch,
    R: RegionAccess,
{
    type Output = LoadedObject<D, Arch, R>;
    type Arch = Arch;

    fn relocate<PreH, PostH, Obs>(
        self,
        args: RelocateArgs<'_, Arch, PreH, PostH, Obs>,
    ) -> Result<Self::Output>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        let inner = self.relocate_impl(args)?;
        Ok(LoadedObject { inner })
    }
}

/// A relocated object file.
pub struct LoadedObject<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) inner: LoadedCore<D, Arch, R, CustomHash>,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Clone for LoadedObject<D, Arch, R> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Debug for LoadedObject<D, Arch, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadedObject")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Deref for LoadedObject<D, Arch, R> {
    type Target = LoadedCore<D, Arch, R, CustomHash>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Borrow<LoadedCore<D, Arch, R, CustomHash>>
    for LoadedObject<D, Arch, R>
{
    fn borrow(&self) -> &LoadedCore<D, Arch, R, CustomHash> {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Borrow<LoadedCore<D, Arch, R, CustomHash>>
    for &LoadedObject<D, Arch, R>
{
    fn borrow(&self) -> &LoadedCore<D, Arch, R, CustomHash> {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> From<LoadedObject<D, Arch, R>>
    for LoadedCore<D, Arch, R, CustomHash>
{
    #[inline]
    fn from(object: LoadedObject<D, Arch, R>) -> Self {
        object.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> From<&LoadedObject<D, Arch, R>>
    for LoadedCore<D, Arch, R, CustomHash>
{
    #[inline]
    fn from(object: &LoadedObject<D, Arch, R>) -> Self {
        object.inner.clone()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> From<LoadedObject<D, Arch, R>>
    for ModuleHandle<Arch>
{
    #[inline]
    fn from(object: LoadedObject<D, Arch, R>) -> Self {
        Self::new(object.inner)
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> From<&LoadedObject<D, Arch, R>>
    for ModuleHandle<Arch>
{
    #[inline]
    fn from(object: &LoadedObject<D, Arch, R>) -> Self {
        Self::new(object.inner.clone())
    }
}
