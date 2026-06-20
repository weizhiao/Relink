//! Executable image types.
//!
//! Use [`RawExec`] for an executable that has been mapped but not yet relocated,
//! and [`LoadedExec`] for the final executable form produced by relocation.

use crate::sync::Arc;
use crate::{
    Result,
    arch::NativeArch,
    elf::ElfPhdr,
    image::{LoadedCore, ModuleTls, RawDynamic},
    input::{Path, PathBuf},
    loader::ImageBuilder,
    memory::{HostRegion, RegionAccess, VmAddr, VmOffset},
    observer::RelocationObserver,
    relocation::{Relocatable, RelocateArgs, RelocationArch, RelocationHandler, Relocator},
    segment::ElfSegments,
    tls::{
        TlsImageProvider, TlsImageSource, TlsModuleId, TlsResolver, TlsTemplate, TlsTpOffset,
        tls_image_provider_handle,
    },
};
use alloc::vec::Vec;
use core::fmt::Debug;

/// A mapped static executable.
///
/// Static executables do not have `PT_DYNAMIC`, so they are ready to run after
/// mapping and any static TLS setup performed by the loader.
pub struct StaticExec<D, Arch: RelocationArch = NativeArch, R: RegionAccess = HostRegion> {
    inner: Arc<StaticExecInner<D, Arch, R>>,
}

// Keep this impl manual so cloning a static executable handle does not require D, Arch, or R to be Clone.
impl<D, Arch: RelocationArch, R: RegionAccess> Clone for StaticExec<D, Arch, R> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D, Arch: RelocationArch, R: RegionAccess> Debug for StaticExec<D, Arch, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticExec")
            .field("path", &self.inner.path)
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> StaticExec<D, Arch, R> {
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

    /// Returns TLS metadata associated with this image.
    pub fn tls(&self) -> ModuleTls {
        ModuleTls::new(self.inner.tls_mod_id, self.inner.tls_tp_offset)
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

struct StaticExecInner<D, Arch: RelocationArch = NativeArch, R: RegionAccess = HostRegion> {
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

    /// TLS module ID
    tls_mod_id: Option<TlsModuleId>,

    /// TLS thread pointer offset
    tls_tp_offset: Option<TlsTpOffset>,

    /// Keeps the static TLS image source alive while the executable is alive.
    _tls_image: Option<Arc<StaticTlsImage>>,
}

struct StaticTlsImage {
    template: TlsTemplate<'static>,
}

impl TlsImageProvider for StaticTlsImage {
    fn with_tls_template(&self, f: &mut dyn FnMut(TlsTemplate<'_>) -> Result<()>) -> Result<()> {
        f(self.template)
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver> Relocatable<D>
    for RawExec<D, Arch, R, Tls>
{
    type Output = LoadedExec<D, Arch, R, Tls>;
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
pub enum RawExec<
    D,
    Arch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver = (),
> where
    D: 'static,
    Arch: RelocationArch,
{
    /// A dynamically linked executable with `PT_DYNAMIC`.
    Dynamic(RawDynamic<D, Arch, R, Tls>),

    /// A statically linked executable without `PT_DYNAMIC`.
    Static(StaticExec<D, Arch, R>),
}

impl<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver> Debug
    for RawExec<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawExec")
            .field("name", &self.name())
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver> RawExec<D, Arch, R, Tls> {
    /// Creates a relocation builder for this executable image.
    pub fn relocator(self) -> Relocator<Self, (), (), Arch, (), Tls> {
        Relocator::<(), (), (), Arch, (), Tls>::new().with_object(self)
    }

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

    /// Returns TLS metadata associated with this executable.
    pub fn tls(&self) -> ModuleTls {
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
    Tls: TlsResolver = (),
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
    Tls: TlsResolver = (),
> {
    Dynamic(LoadedCore<D, Arch, R, Tls>),
    Static(StaticExec<D, Arch, R>),
}

// Keep this impl manual so cloning a loaded executable does not require D, Arch, or R to be Clone.
impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver> Clone
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

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver> Clone
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

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver>
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

    /// Returns TLS metadata associated with this executable.
    pub fn tls(&self) -> ModuleTls {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.tls(),
            LoadedExecInner::Static(static_image) => static_image.tls(),
        }
    }
}

impl<D, Arch: RelocationArch, R: RegionAccess> StaticExec<D, Arch, R> {
    pub(crate) fn from_builder<Tls>(
        mut builder: ImageBuilder<Tls, D, Arch, R>,
        phdrs: &[ElfPhdr<Arch::Layout>],
    ) -> Result<Self>
    where
        Tls: TlsResolver,
    {
        // Parse all program headers
        builder.parse_phdrs(phdrs)?;

        let entry = VmAddr::new(builder.ehdr.e_entry());
        let mut tls_image = None;
        let (tls_mod_id, tls_tp_offset) = if let Some(info) = &builder.tls_info {
            let template = builder
                .segments
                .read_view::<u8>(VmOffset::new(info.vaddr), info.filesz)
                .ok_or_else(|| crate::ParsePhdrError::malformed("PT_TLS image is malformed"))?;
            tls_image = Some(Arc::new(StaticTlsImage {
                template: (*info).template(template.as_slice()),
            }));
            // Static executables always use static TLS if PT_TLS is present.
            let (mod_id, offset) = Tls::register_static(info)?;
            (Some(mod_id), Some(offset))
        } else {
            (None, None)
        };

        let inner = Arc::new(StaticExecInner {
            entry,
            path: builder.path,
            user_data: builder.user_data,
            segments: builder.segments,
            phdrs: if phdrs.is_empty() {
                None
            } else {
                Some(phdrs.to_vec())
            },
            tls_mod_id,
            tls_tp_offset,
            _tls_image: tls_image.clone(),
        });

        if let (Some(mod_id), Some(offset), Some(image)) =
            (tls_mod_id, tls_tp_offset, tls_image.as_ref())
        {
            let provider = tls_image_provider_handle(image.clone());
            Tls::init_tls(
                TlsImageSource::new(image.template.info, Arc::downgrade(&provider)),
                mod_id,
                Some(offset),
            )?;
        }

        Ok(StaticExec { inner })
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver> RawExec<D, Arch, R, Tls> {
    pub(crate) fn from_builder(
        builder: ImageBuilder<Tls, D, Arch, R>,
        phdrs: &[ElfPhdr<Arch::Layout>],
        has_dynamic: bool,
    ) -> Result<Self> {
        if has_dynamic {
            Ok(Self::Dynamic(RawDynamic::from_builder(builder, phdrs)?))
        } else {
            Ok(Self::Static(StaticExec::from_builder(builder, phdrs)?))
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
