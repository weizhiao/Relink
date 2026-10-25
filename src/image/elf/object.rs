//! Relocatable ELF file handling
//!
//! This module provides functionality for loading and relocating relocatable
//! ELF files (also known as object files). These are typically `.o` files that
//! contain code and data that need to be relocated before they can be executed.

use crate::object::{
    ObjectBuilder, ObjectSections, ObjectSymbolTable, PltGotSection, SectionSegments,
};
use crate::segment::ElfSegments;
use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfSectionId, Lifecycle},
    image::{
        CoreRuntime, ElfCore, ElfModule, ExportTable, LoadedCore, ModuleHandle, ModuleSearch,
        ModuleState,
    },
    lazy::LazyBinder,
    memory::{HostRegion, RegionAccess},
    observer::RelocationObserver,
    relocation::{ObjectArch, Relocatable, RelocateArgs, RelocationArch},
    runtime::Domain,
    sync::{Arc, OnceCell},
    tls::{ImageTlsState, TlsResolver},
};
use core::{fmt::Debug, ops::Deref};

/// A relocatable ELF object.
///
/// This structure represents a relocatable ELF file (typically a `.o` file)
/// that has been loaded into memory and is ready for relocation. It contains
/// all the necessary information to perform the relocation process.
pub struct RawObject<
    D: Send + Sync + 'static = (),
    Arch: ObjectArch = NativeArch,
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

impl<D: Send + Sync + 'static, Arch: ObjectArch, R: RegionAccess, Tls: TlsResolver<Arch>> Deref
    for RawObject<D, Arch, R, Tls>
{
    type Target = ElfCore<D, Arch, R, Tls>;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<Tls, D: Send + Sync + 'static, Arch, R> ObjectBuilder<Tls, D, Arch, R>
where
    Tls: TlsResolver<Arch>,
    Arch: ObjectArch,
    R: RegionAccess,
{
    pub(crate) fn build_object(self) -> RawObject<D, Arch, R, Tls> {
        let (segments, init_segments) = self.segments.into_parts();
        let inner = ElfModule {
            runtime: CoreRuntime::new::<D, R, Tls>(None),
            state: ModuleState::new(self.source_id, self.domain.id()),
            lifecycle: OnceCell::new(),
            search: ModuleSearch::from_dynamic(self.path, None, None, None),
            exports: ExportTable::pending_object(),
            user_data: self.user_data,
            dynamic_info: None,
            lazy_lookup: OnceCell::new(),
            tls: ImageTlsState::empty(),
            domain: self.domain,
            segments,
        };
        let inner = Arc::new(inner);
        ElfModule::bind_runtime_owner(&inner);

        RawObject {
            core: ElfCore { inner },
            symtab: self.symtab,
            sections: self.sections,
            pltgot: self.pltgot,
            section_segments: self.section_segments,
            init_segments,
            init: self.init,
            fini: self.fini,
        }
    }
}

impl<D: Send + Sync + 'static, Arch: ObjectArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    RawObject<D, Arch, R, Tls>
{
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

impl<D: Send + Sync + 'static, Arch: ObjectArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for RawObject<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawObject")
            .field("core", &self.core)
            .finish()
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> Relocatable<D> for RawObject<D, Arch, R, Tls>
where
    Arch: ObjectArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    type Output = LoadedObject<D, Arch, R, Tls>;
    type Arch = Arch;
    type Tls = Tls;

    fn domain(&self) -> &Domain<Arch, Tls> {
        self.core.domain()
    }

    fn relocate<Obs, Binder>(
        self,
        args: RelocateArgs<'_, Arch, Obs, Binder>,
    ) -> Result<Self::Output>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
        Binder: LazyBinder<Arch> + ?Sized,
    {
        self.relocate_impl(args)
    }
}

/// A relocated object file.
pub struct LoadedObject<
    D: Send + Sync + 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    pub(crate) inner: LoadedCore<D, Arch, R, Tls>,
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for LoadedObject<D, Arch, R, Tls>
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for LoadedObject<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadedObject")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Deref
    for LoadedObject<D, Arch, R, Tls>
{
    type Target = LoadedCore<D, Arch, R, Tls>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    From<LoadedObject<D, Arch, R, Tls>> for LoadedCore<D, Arch, R, Tls>
{
    #[inline]
    fn from(object: LoadedObject<D, Arch, R, Tls>) -> Self {
        object.inner
    }
}

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> From<LoadedObject<D, Arch, R, Tls>> for ModuleHandle<Arch>
{
    #[inline]
    fn from(object: LoadedObject<D, Arch, R, Tls>) -> Self {
        Self::new(object.inner)
    }
}

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> From<&LoadedObject<D, Arch, R, Tls>> for ModuleHandle<Arch>
{
    #[inline]
    fn from(object: &LoadedObject<D, Arch, R, Tls>) -> Self {
        Self::new(object.inner.clone())
    }
}
