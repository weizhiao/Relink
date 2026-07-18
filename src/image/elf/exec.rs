//! Executable image types.
//!
//! Use [`RawExec`] for an executable that has been mapped but not yet relocated,
//! and [`LoadedExec`] for the final executable form produced by relocation.

use crate::sync::Arc;
use crate::{
    ParsePhdrError, Result,
    arch::NativeArch,
    elf::ElfPhdr,
    image::{LoadedCore, RawDynamic},
    input::{Path, PathBuf},
    lazy::{LazyBinder, SupportLazy},
    loader::ImageBuilder,
    memory::{HostRegion, RegionAccess, VmAddr, VmOffset},
    observer::RelocationObserver,
    relocation::{Relocatable, RelocateArgs, RelocationArch},
    runtime::DomainId,
    segment::ElfSegments,
    tls::{
        ModuleTls, TlsImageProvider, TlsImageSource, TlsRequest, TlsResolver,
        tls_image_provider_handle,
    },
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
impl<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for StaticExec<D, Arch, R, Tls>
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for StaticExec<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticExec")
            .field("path", &self.inner.path)
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    StaticExec<D, Arch, R, Tls>
{
    /// Returns the source path or caller-provided path identifier.
    pub fn path(&self) -> &Path {
        self.inner.path.as_path()
    }

    /// Returns the final path component.
    pub fn name(&self) -> &str {
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
    pub fn tls(&self) -> Option<ModuleTls> {
        self.inner.tls
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

    /// TLS module placement.
    tls: Option<ModuleTls>,

    /// Resolver that owns the TLS registration.
    tls_resolver: Tls,

    /// Runtime domain in which this executable was loaded.
    domain: DomainId,

    /// Keeps the static TLS image source alive while the executable is alive.
    _tls_image: Option<Arc<StaticTlsImage>>,
}

impl<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Drop
    for StaticExecInner<D, Arch, R, Tls>
{
    fn drop(&mut self) {
        if let Some(tls) = self.tls {
            self.tls_resolver.unregister(tls.mod_id());
        }
    }
}

struct StaticTlsImage {
    image: &'static [u8],
}

impl TlsImageProvider for StaticTlsImage {
    fn with_tls_image(&self, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        f(self.image)
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Relocatable<D>
    for RawExec<D, Arch, R, Tls>
{
    type Output = LoadedExec<D, Arch, R, Tls>;
    type Arch = Arch;
    type Tls = Tls;

    fn domain_id(&self) -> DomainId {
        match self {
            Self::Dynamic(image) => image.core_ref().domain_id(),
            Self::Static(image) => image.inner.domain,
        }
    }

    fn relocate<Obs, Binder>(
        self,
        args: RelocateArgs<'_, Arch, Tls, Obs, Binder>,
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

/// A mapped but unrelocated executable image.
///
/// Values of this type are returned by [`crate::Loader::load_exec`]. They may
/// represent either a dynamic executable that still needs relocation or a
/// static executable that is already ready to run.
///
/// The optional `Arch` type parameter is forwarded to the underlying
/// [`RawDynamic`] for dynamic executables. Static executables ignore it but
/// still carry it so that downstream APIs can treat both variants uniformly.
///
/// The dynamic variant intentionally stays inline to avoid changing the public
/// enum shape or adding an allocation to executable loading.
#[allow(clippy::large_enum_variant)]
pub enum RawExec<D, Arch = NativeArch, R: RegionAccess = HostRegion, Tls: TlsResolver<Arch> = ()>
where
    D: 'static,
    Arch: RelocationArch,
{
    /// A dynamically linked executable with `PT_DYNAMIC`.
    Dynamic(RawDynamic<D, Arch, R, Tls>),

    /// A statically linked executable without `PT_DYNAMIC`.
    Static(StaticExec<D, Arch, R, Tls>),
}

impl<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for RawExec<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawExec")
            .field("name", &self.name())
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> SupportLazy
    for RawExec<D, Arch, R, Tls>
{
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
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
    pub fn name(&self) -> &str {
        match self {
            RawExec::Dynamic(image) => image.name(),
            RawExec::Static(image) => image.name(),
        }
    }

    /// Returns the entry point of the executable.
    pub fn entry(&self) -> usize {
        match self {
            RawExec::Dynamic(image) => image.entry(),
            RawExec::Static(image) => image.entry(),
        }
    }

    /// Returns TLS metadata when this executable owns a TLS block.
    pub fn tls(&self) -> Option<ModuleTls> {
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
    pub fn needed_libs(&self) -> &[&str] {
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
            RawExec::Dynamic(image) => image.base(),
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
    D: 'static,
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
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    Dynamic(LoadedCore<D, Arch, R, Tls>),
    Static(StaticExec<D, Arch, R, Tls>),
}

// Keep this impl manual so cloning a loaded executable does not require D, Arch, or R to be Clone.
impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
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

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
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

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
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
    pub fn name(&self) -> &str {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.name(),
            LoadedExecInner::Static(static_image) => static_image.name(),
        }
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
        match &self.inner {
            LoadedExecInner::Dynamic(_) => false,
            LoadedExecInner::Static(_) => true,
        }
    }

    /// Returns a reference to the core ELF object if this is a dynamic executable.
    /// Returns the loaded dynamic core, or `None` for static executables.
    pub fn core_ref(&self) -> Option<&LoadedCore<D, Arch, R, Tls>> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => Some(module),
            LoadedExecInner::Static(_) => None,
        }
    }

    /// Returns TLS metadata when this executable owns a TLS block.
    pub fn tls(&self) -> Option<ModuleTls> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.tls(),
            LoadedExecInner::Static(static_image) => static_image.tls(),
        }
    }
}

impl<Tls, D: 'static, Arch: RelocationArch, R: RegionAccess> ImageBuilder<Tls, D, Arch, R>
where
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn build_static_exec(
        mut self,
        phdrs: &[ElfPhdr<Arch::Layout>],
    ) -> Result<StaticExec<D, Arch, R, Tls>> {
        self.parse_phdrs(phdrs)?;

        let entry = self.entry;
        let mut tls_image = None;
        let module_tls = if let Some(info) = &self.tls_info {
            let image = self
                .segments
                .read_view::<u8>(VmOffset::new(info.vaddr), info.filesz)
                .ok_or_else(|| ParsePhdrError::malformed("PT_TLS image is malformed"))?;
            tls_image = Some(Arc::new(StaticTlsImage {
                image: image.as_slice(),
            }));
            // Static executables always use static TLS if PT_TLS is present.
            Some(
                self.tls_resolver
                    .register(*info, TlsRequest::Static(None))?,
            )
        } else {
            None
        };

        let inner = Arc::new(StaticExecInner {
            entry,
            path: self.path,
            user_data: self.user_data,
            segments: self.segments,
            phdrs: if phdrs.is_empty() {
                None
            } else {
                Some(phdrs.to_vec())
            },
            tls: module_tls,
            tls_resolver: self.tls_resolver.clone(),
            domain: self.domain,
            _tls_image: tls_image.clone(),
        });

        if let Some(image) = tls_image.as_ref() {
            let provider = tls_image_provider_handle(image.clone());
            let mod_id = module_tls
                .expect("static TLS image must have registered module metadata")
                .mod_id();
            self.tls_resolver
                .publish(TlsImageSource::new(Arc::downgrade(&provider)), mod_id)?;
        }

        Ok(StaticExec { inner })
    }

    pub(crate) fn build_exec(
        self,
        phdrs: &[ElfPhdr<Arch::Layout>],
        has_dynamic: bool,
    ) -> Result<RawExec<D, Arch, R, Tls>> {
        if has_dynamic {
            Ok(RawExec::Dynamic(self.build_dynamic(phdrs)?))
        } else {
            Ok(RawExec::Static(self.build_static_exec(phdrs)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NonCloneData;

    #[test]
    fn exec_handles_clone_without_user_data_clone() {
        fn assert_clone<T: Clone>() {}

        assert_clone::<StaticExec<NonCloneData>>();
        assert_clone::<LoadedExec<NonCloneData>>();
    }
}
