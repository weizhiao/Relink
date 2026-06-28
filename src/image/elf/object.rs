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
    memory::{HostRegion, RegionAccess},
    observer::RelocationObserver,
    relocation::{
        ObjectRelocationArch, Relocatable, RelocateArgs, RelocationArch, RelocationHandler,
        Relocator,
    },
    sync::{Arc, AtomicBool},
    tls::{CoreTlsState, TlsResolver},
};
use alloc::boxed::Box;
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
    Tls: TlsResolver<Arch> = (),
> {
    /// Core component containing basic ELF information.
    pub(crate) core: ElfCore<D, Arch, R, Tls>,

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

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Deref
    for RawObject<D, Arch, R, Tls>
{
    type Target = ElfCore<D, Arch, R, Tls>;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    RawObject<D, Arch, R, Tls>
{
    pub(crate) fn from_builder(mut builder: ObjectBuilder<Tls, D, Arch, R>) -> Self {
        let (segments, init_segments) = builder.segments.into_parts();
        let pltgot = builder.section_segments.take_pltgot();
        let inner = CoreInner {
            runtime: Box::new(crate::image::CoreRuntime::new::<D, R, Tls>(None)),
            is_init: AtomicBool::new(false),
            path: builder.path,
            exports: exports_handle(ObjectExports::<Arch::Layout>::empty()),
            finalizer: OnceCell::new(),
            user_data: builder.user_data,
            dynamic_info: None,
            scope: OnceCell::new(),
            tls: CoreTlsState::new(builder.tls_mod_id, builder.tls_tp_offset, None, None),
            segments,
        };
        let inner = Arc::new(inner);
        CoreInner::bind_runtime_owner(&inner);

        Self {
            core: ElfCore { inner },
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
    pub fn relocator(self) -> Relocator<Self, (), (), Arch, (), Tls>
    where
        Self: Relocatable<D, Arch = Arch, Tls = Tls>,
    {
        Relocator::<(), (), (), Arch, (), Tls>::new().with_object(self)
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

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for RawObject<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawObject")
            .field("core", &self.core)
            .finish()
    }
}

impl<D: 'static, Arch, R, Tls> Relocatable<D> for RawObject<D, Arch, R, Tls>
where
    Arch: ObjectRelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    type Output = LoadedObject<D, Arch, R, Tls>;
    type Arch = Arch;
    type Tls = Tls;

    fn relocate<PreH, PostH, Obs>(
        self,
        args: RelocateArgs<'_, Arch, Tls, PreH, PostH, Obs>,
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
    Tls: TlsResolver<Arch> = (),
> {
    pub(crate) inner: LoadedCore<D, Arch, R, Tls>,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for LoadedObject<D, Arch, R, Tls>
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for LoadedObject<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadedObject")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Deref
    for LoadedObject<D, Arch, R, Tls>
{
    type Target = LoadedCore<D, Arch, R, Tls>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    Borrow<LoadedCore<D, Arch, R, Tls>> for LoadedObject<D, Arch, R, Tls>
{
    fn borrow(&self) -> &LoadedCore<D, Arch, R, Tls> {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    Borrow<LoadedCore<D, Arch, R, Tls>> for &LoadedObject<D, Arch, R, Tls>
{
    fn borrow(&self) -> &LoadedCore<D, Arch, R, Tls> {
        &self.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    From<LoadedObject<D, Arch, R, Tls>> for LoadedCore<D, Arch, R, Tls>
{
    #[inline]
    fn from(object: LoadedObject<D, Arch, R, Tls>) -> Self {
        object.inner
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    From<&LoadedObject<D, Arch, R, Tls>> for LoadedCore<D, Arch, R, Tls>
{
    #[inline]
    fn from(object: &LoadedObject<D, Arch, R, Tls>) -> Self {
        object.inner.clone()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> + 'static>
    From<LoadedObject<D, Arch, R, Tls>> for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn from(object: LoadedObject<D, Arch, R, Tls>) -> Self {
        Self::new(object.inner)
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> + 'static>
    From<&LoadedObject<D, Arch, R, Tls>> for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn from(object: &LoadedObject<D, Arch, R, Tls>) -> Self {
        Self::new(object.inner.clone())
    }
}
