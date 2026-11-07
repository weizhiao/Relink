//! Executable image types.
//!
//! Use [`RawExec`] for an executable that has been mapped but not yet relocated,
//! and [`LoadedExec`] for the final executable form produced by relocation.

use crate::{
    ParsePhdrError, Result,
    arch::NativeArch,
    elf::ElfPhdr,
    image::{LoadedCore, Module, RawDynamic, SearchPathPool},
    input::{Path, PathBuf},
    lazy::{LazyBinder, SupportLazy},
    loader::ImageBuilder,
    memory::{HostRegion, RegionAccess, VmAddr, VmOffset},
    observer::RelocationObserver,
    relocation::{Relocatable, RelocateArgs, RelocationArch},
    runtime::Domain,
    segment::ElfSegments,
    sync::Arc,
    tls::{ImageTlsState, TlsModule, TlsRequest, TlsResolver},
};
use alloc::vec::Vec;
use core::fmt::Debug;

/// A mapped static executable.
///
/// Static executables do not have `PT_DYNAMIC`, so they are ready to run after
/// mapping and any static TLS setup performed by the loader.
pub struct StaticExec<
    D,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    inner: Arc<StaticExecInner<D, Arch, R, Tls>>,
}

// Keep this impl manual so cloning a static executable handle does not require D, Arch, or R to be Clone.
impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for StaticExec<D, Arch, R, Tls>
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for StaticExec<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticExec")
            .field("path", &self.inner.path)
            .finish()
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    StaticExec<D, Arch, R, Tls>
{
    /// Returns the source path or caller-provided path identifier.
    pub fn path(&self) -> &Path {
        self.inner.path.as_path()
    }

    /// Returns the final path component.
    pub fn name(&self) -> &[u8] {
        self.path().file_name()
    }

    /// Returns the executable entry point address.
    pub fn entry(&self) -> usize {
        self.entry_addr().get()
    }

    pub(crate) fn entry_addr(&self) -> VmAddr {
        self.inner.entry
    }

    /// Returns TLS metadata when this image owns a TLS block.
    pub fn tls(&self) -> Option<&TlsModule> {
        self.inner.tls.module()
    }

    /// Returns user data associated with the image.
    pub fn user_data(&self) -> &D {
        &self.inner.user_data
    }

    /// Returns program headers when they were retained by the loader.
    pub fn phdrs(&self) -> Option<&[ElfPhdr<Arch::Layout>]> {
        self.inner.phdrs.as_deref()
    }

    /// Returns the runtime base address.
    pub fn base(&self) -> VmAddr {
        self.inner.segments.base()
    }

    /// Returns the mapped segments owned by this executable.
    pub fn segments(&self) -> &ElfSegments<R> {
        &self.inner.segments
    }
}

struct StaticExecInner<
    D,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    // Descriptor state is cleared before unregistering in Drop.
    tls: ImageTlsState,
    domain: Domain<Arch, Tls>,

    /// Loader source path or caller-provided source identifier.
    path: PathBuf,

    /// Entry point of the executable
    entry: VmAddr,

    /// User-defined data
    user_data: D,

    /// Memory segments
    segments: ElfSegments<R>,

    /// Program headers
    phdrs: Option<Vec<ElfPhdr<Arch::Layout>>>,
}

impl<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Drop
    for StaticExecInner<D, Arch, R, Tls>
{
    fn drop(&mut self) {
        self.tls.release();
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    Relocatable<D> for RawExec<D, Arch, R, Tls>
{
    type Output = LoadedExec<D, Arch, R, Tls>;
    type Arch = Arch;
    type Tls = Tls;

    fn domain(&self) -> &Domain<Arch, Tls> {
        match self {
            Self::Dynamic(image) => image.domain(),
            Self::Static(image) => &image.inner.domain,
        }
    }

    fn relocate<Obs, Binder>(
        self,
        args: RelocateArgs<'_, Arch, Obs, Binder>,
    ) -> Result<Self::Output>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
        Binder: LazyBinder<Arch> + ?Sized,
    {
        match self {
            RawExec::Dynamic(image) => {
                let entry = image.entry_addr();
                let inner = Relocatable::relocate(image, args)?;
                Ok(LoadedExec {
                    entry,
                    inner: LoadedExecInner::Dynamic(inner),
                })
            }
            RawExec::Static(image) => Ok(LoadedExec {
                entry: image.entry_addr(),
                inner: LoadedExecInner::Static(image),
            }),
        }
    }
}

/// An executable mapped by [`crate::LoaderRun::load_exec`].
/// Static executables are ready to use; dynamic executables need relocation
/// through [`crate::Relocator::run`].
#[allow(clippy::large_enum_variant)]
pub enum RawExec<D, Arch = NativeArch, R: RegionAccess = HostRegion, Tls: TlsResolver<Arch> = ()>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
{
    /// A dynamically linked executable with `PT_DYNAMIC`.
    Dynamic(RawDynamic<D, Arch, R, Tls>),

    /// A statically linked executable without `PT_DYNAMIC`.
    Static(StaticExec<D, Arch, R, Tls>),
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for RawExec<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawExec")
            .field("name", &self.name())
            .finish()
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    SupportLazy for RawExec<D, Arch, R, Tls>
{
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    RawExec<D, Arch, R, Tls>
{
    /// Returns the loader source path or caller-provided source identifier.
    pub fn path(&self) -> &Path {
        match self {
            RawExec::Dynamic(image) => image.path(),
            RawExec::Static(image) => image.path(),
        }
    }

    /// Returns the executable identity used for diagnostics.
    pub fn name(&self) -> &[u8] {
        self.path().file_name()
    }

    /// Returns the entry point of the executable.
    pub fn entry(&self) -> usize {
        match self {
            RawExec::Dynamic(image) => image.entry(),
            RawExec::Static(image) => image.entry(),
        }
    }

    /// Returns TLS metadata when this executable owns a TLS block.
    pub fn tls(&self) -> Option<&TlsModule> {
        match self {
            RawExec::Dynamic(image) => image.tls(),
            RawExec::Static(image) => image.tls(),
        }
    }

    /// Returns the PT_INTERP value.
    pub fn interp(&self) -> Option<&str> {
        match self {
            RawExec::Dynamic(image) => image.interp(),
            RawExec::Static(_) => None,
        }
    }

    /// Returns the list of needed library names from the dynamic section.
    pub fn needed_libs(&self) -> &[&[u8]] {
        match self {
            RawExec::Dynamic(image) => image.needed_libs(),
            RawExec::Static(_) => &[],
        }
    }

    /// Returns the program headers of the executable.
    pub fn phdrs(&self) -> Option<&[ElfPhdr<Arch::Layout>]> {
        match self {
            RawExec::Dynamic(image) => Some(image.phdrs()),
            RawExec::Static(image) => image.phdrs(),
        }
    }

    /// Returns whether `addr` is inside one of this executable's mapped slices.
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
        match self {
            RawExec::Dynamic(image) => image.segments().contains_addr(addr),
            RawExec::Static(image) => image.segments().contains_addr(addr),
        }
    }

    /// Returns the runtime base address.
    pub fn base(&self) -> VmAddr {
        match self {
            RawExec::Dynamic(image) => image.segments().base(),
            RawExec::Static(image) => image.base(),
        }
    }
}

/// A relocated executable image.
///
/// Dynamic executables retain access to their underlying [`LoadedCore`], while
/// static executables expose a smaller set of metadata directly on this wrapper.
#[derive(Debug)]
pub struct LoadedExec<
    D: Send + Sync + 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    /// Entry point of the executable.
    entry: VmAddr,
    /// The relocated ELF object.
    inner: LoadedExecInner<D, Arch, R, Tls>,
}

#[derive(Debug)]
enum LoadedExecInner<
    D: Send + Sync + 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    Dynamic(LoadedCore<D, Arch, R, Tls>),
    Static(StaticExec<D, Arch, R, Tls>),
}

// Keep this impl manual so cloning a loaded executable does not require D, Arch, or R to be Clone.
impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for LoadedExec<D, Arch, R, Tls>
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            entry: self.entry,
            inner: self.inner.clone(),
        }
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for LoadedExecInner<D, Arch, R, Tls>
{
    #[inline]
    fn clone(&self) -> Self {
        match self {
            Self::Dynamic(module) => Self::Dynamic(module.clone()),
            Self::Static(module) => Self::Static(module.clone()),
        }
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    LoadedExec<D, Arch, R, Tls>
{
    /// Returns the entry point of the executable.
    #[inline]
    pub fn entry(&self) -> usize {
        self.entry.get()
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.path(),
            LoadedExecInner::Static(static_image) => static_image.path(),
        }
    }

    /// Returns the executable identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &[u8] {
        self.path().file_name()
    }

    /// Returns whether `addr` is inside one of this executable's mapped slices.
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.segments().contains_addr(addr),
            LoadedExecInner::Static(static_image) => static_image.segments().contains_addr(addr),
        }
    }

    /// Returns a reference to the user-defined data associated with this executable.
    pub fn user_data(&self) -> &D {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.user_data(),
            LoadedExecInner::Static(static_image) => &static_image.inner.user_data,
        }
    }

    /// Returns whether this executable was loaded as a static binary.
    pub fn is_static(&self) -> bool {
        matches!(&self.inner, LoadedExecInner::Static(_))
    }

    /// Returns the loaded dynamic core, or `None` for static executables.
    pub fn core_ref(&self) -> Option<&LoadedCore<D, Arch, R, Tls>> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => Some(module),
            LoadedExecInner::Static(_) => None,
        }
    }

    /// Returns TLS metadata when this executable owns a TLS block.
    pub fn tls(&self) -> Option<&TlsModule> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.tls(),
            LoadedExecInner::Static(static_image) => static_image.tls(),
        }
    }

    /// Returns the runtime base address.
    pub fn base(&self) -> VmAddr {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.segments().base(),
            LoadedExecInner::Static(static_image) => static_image.base(),
        }
    }
}

impl<Tls, D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess>
    ImageBuilder<Tls, D, Arch, R>
where
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn build_static_exec(
        mut self,
        phdrs: &[ElfPhdr<Arch::Layout>],
    ) -> Result<StaticExec<D, Arch, R, Tls>> {
        self.parse_phdrs(phdrs)?;

        let entry = self.entry;
        let tls = if let Some(info) = &self.tls_info {
            let image = self
                .segments
                .read_view::<u8>(VmOffset::new(info.vaddr), info.filesz)
                .ok_or_else(|| ParsePhdrError::malformed("PT_TLS image is malformed"))?;
            // Static executables always use static TLS if PT_TLS is present.
            let module = self
                .domain
                .tls_resolver()
                .register(*info, TlsRequest::Static(None))?;
            ImageTlsState::owned(module, image)
        } else {
            ImageTlsState::empty()
        };

        let inner = StaticExecInner {
            tls,
            domain: self.domain,
            entry,
            path: self.path,
            user_data: self.user_data,
            segments: self.segments,
            phdrs: if phdrs.is_empty() {
                None
            } else {
                Some(phdrs.to_vec())
            },
        };
        let inner = Arc::new(inner);

        if let Some(module) = inner.tls.module() {
            inner
                .domain
                .tls_resolver()
                .publish(inner.tls.template()?, module.mod_id())?;
        }

        Ok(StaticExec { inner })
    }

    pub(crate) fn build_exec(
        self,
        phdrs: &[ElfPhdr<Arch::Layout>],
        has_dynamic: bool,
        search_paths: Option<&mut SearchPathPool>,
    ) -> Result<RawExec<D, Arch, R, Tls>> {
        if has_dynamic {
            Ok(RawExec::Dynamic(self.build_dynamic(phdrs, search_paths)?))
        } else {
            Ok(RawExec::Static(self.build_static_exec(phdrs)?))
        }
    }
}
