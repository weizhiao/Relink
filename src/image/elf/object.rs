//! Relocatable ELF file handling
//!
//! This module provides functionality for loading and relocating relocatable
//! ELF files (also known as object files). These are typically `.o` files that
//! contain code and data that need to be relocated before they can be executed.

use crate::object::{
    ObjectBuilder, ObjectExports, ObjectSections, ObjectSymbolTable, PltGotSection, SectionSegments,
};
use crate::segment::ElfSegments;
use crate::{
    Result,
    elf::{ElfSectionId, Lifecycle},
    image::exports_handle,
    memory::{HostRegion, RegionAccess, VmAddr},
    observer::RelocationObserver,
    relocation::{
        ObjectRelocationArch, Relocatable, RelocateArgs, RelocationArch, RelocationHandler,
        Relocator,
    },
    sync::{Arc, AtomicBool},
    tls::{CoreTlsState, TlsResolver},
};
use core::{borrow::Borrow, cell::OnceCell, fmt::Debug, ops::Deref};

use crate::image::{ElfCore, LoadedCore, ModuleHandle, core::CoreInner};

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
    pub(crate) core: ElfCore<D, Arch, R>,

    /// Relocation-only object symbol table.
    pub(crate) symtab: ObjectSymbolTable<Arch::Layout>,

    /// Rebased section headers paired with their section-name string table.
    pub(crate) sections: ObjectSections<Arch::Layout>,

    /// PLT/GOT section information.
    pub(crate) pltgot: PltGotSection,

    /// Section segment layout and protection metadata.
    pub(crate) section_segments: SectionSegments<Arch>,

    /// Initialization-only mapped memory.
    pub(crate) init_segments: Option<ElfSegments<R>>,

    /// Initialization lifecycle.
    pub(crate) init: Lifecycle,

    /// Finalization lifecycle.
    pub(crate) fini: Lifecycle,
}

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess> Deref for RawObject<D, Arch, R> {
    type Target = ElfCore<D, Arch, R>;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess> RawObject<D, Arch, R> {
    pub(crate) fn from_builder<T: TlsResolver>(mut builder: ObjectBuilder<T, D, Arch, R>) -> Self {
        let (segments, init_segments) = builder.segments.into_parts();
        let pltgot = builder.section_segments.take_pltgot();
        let inner = CoreInner {
            is_init: AtomicBool::new(false),
            path: builder.path,
            exports: exports_handle(ObjectExports::<Arch::Layout>::empty()),
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
            symtab: builder.symtab,
            sections: builder.sections,
            pltgot,
            section_segments: builder.section_segments,
            init_segments,
            init: builder.init,
            fini: builder.fini,
        }
    }

    /// Creates a builder for relocating the relocatable file.
    pub fn relocator(self) -> Relocator<Self, (), (), Arch>
    where
        Self: Relocatable<D, Arch = Arch>,
    {
        Relocator::<(), (), (), Arch>::new().with_object(self)
    }

    /// Returns the retained object section metadata.
    #[inline]
    pub fn sections(&self) -> &ObjectSections<Arch::Layout> {
        &self.sections
    }

    #[inline]
    pub(crate) fn section_is_mapped(&self, id: ElfSectionId) -> bool {
        self.sections.section_is_mapped(id)
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
        self.relocate_impl(args)
    }
}

/// A relocated object file.
pub struct LoadedObject<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) inner: LoadedCore<D, Arch, R>,
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
    type Target = LoadedCore<D, Arch, R>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Borrow<LoadedCore<D, Arch, R>>
    for LoadedObject<D, Arch, R>
{
    fn borrow(&self) -> &LoadedCore<D, Arch, R> {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Borrow<LoadedCore<D, Arch, R>>
    for &LoadedObject<D, Arch, R>
{
    fn borrow(&self) -> &LoadedCore<D, Arch, R> {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> From<LoadedObject<D, Arch, R>>
    for LoadedCore<D, Arch, R>
{
    #[inline]
    fn from(object: LoadedObject<D, Arch, R>) -> Self {
        object.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> From<&LoadedObject<D, Arch, R>>
    for LoadedCore<D, Arch, R>
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
