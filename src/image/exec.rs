//! Executable image types.
//!
//! Use [`RawExec`] for an executable that has been mapped but not yet relocated,
//! and [`LoadedExec`] for the final executable form produced by relocation.

use crate::sync::Arc;
use crate::{
    Result,
    arch::NativeArch,
    elf::ElfPhdr,
    image::{LoadedCore, RawDynamic},
    loader::{ImageBuilder, LoadHook},
    os::Mmap,
    relocation::{
        RelocAddr, Relocatable, RelocateArgs, RelocationArch, RelocationHandler, Relocator,
        SymbolLookup,
    },
    segment::ElfSegments,
    tls::{TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::{string::String, vec::Vec};
use core::fmt::Debug;

/// A mapped static executable.
///
/// Static executables do not have `PT_DYNAMIC`, so they are ready to run after
/// mapping and any static TLS setup performed by the loader.
#[derive(Clone)]
pub struct StaticExec<D, Arch: RelocationArch = NativeArch> {
    inner: Arc<StaticExecInner<D, Arch>>,
}

impl<D, Arch: RelocationArch> Debug for StaticExec<D, Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticExec")
            .field("name", &self.inner.name)
            .finish()
    }
}

impl<D, Arch: RelocationArch> StaticExec<D, Arch> {
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn entry(&self) -> usize {
        self.entry_addr().into_inner()
    }

    pub(crate) fn entry_addr(&self) -> RelocAddr {
        self.inner.entry
    }

    pub fn tls_mod_id(&self) -> Option<TlsModuleId> {
        self.inner.tls_mod_id
    }

    pub fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        self.inner.tls_tp_offset
    }

    pub fn user_data(&self) -> &D {
        &self.inner.user_data
    }

    pub fn phdrs(&self) -> Option<&[ElfPhdr<Arch::Layout>]> {
        self.inner.phdrs.as_deref()
    }

    pub fn base(&self) -> usize {
        self.inner.segments.base()
    }

    pub(crate) fn mapped_base(&self) -> usize {
        self.inner.segments.mapped_base()
    }

    pub fn mapped_len(&self) -> usize {
        self.inner.segments.mapped_len()
    }

    pub fn contains_addr(&self, addr: usize) -> bool {
        self.inner.segments.contains_addr(addr)
    }
}

struct StaticExecInner<D, Arch: RelocationArch = NativeArch> {
    /// File name of the ELF object
    name: String,

    /// Entry point of the executable
    entry: RelocAddr,

    /// User-defined data
    user_data: D,

    /// Memory segments
    segments: ElfSegments,

    /// Program headers
    phdrs: Option<Vec<ElfPhdr<Arch::Layout>>>,

    /// TLS module ID
    tls_mod_id: Option<TlsModuleId>,

    /// TLS thread pointer offset
    tls_tp_offset: Option<TlsTpOffset>,
}

impl<D: 'static, Arch: RelocationArch> Relocatable<D> for RawExec<D, Arch> {
    type Output = LoadedExec<D, Arch>;
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

#[cfg(feature = "lazy-binding")]
impl<D: 'static, Arch: RelocationArch> crate::relocation::SupportLazy for RawExec<D, Arch> {}

/// A mapped but unrelocated executable image.
///
/// Values of this type are returned by [`crate::Loader::load_exec`]. They may
/// represent either a dynamic executable that still needs relocation or a
/// static executable that is already ready to run.
///
/// The optional `Arch` type parameter is forwarded to the underlying
/// [`RawDynamic`] for dynamic executables. Static executables ignore it but
/// still carry it so that downstream APIs can treat both variants uniformly.
pub enum RawExec<D, Arch = crate::arch::NativeArch>
where
    D: 'static,
    Arch: RelocationArch,
{
    /// A dynamically linked executable with `PT_DYNAMIC`.
    Dynamic(RawDynamic<D, Arch>),

    /// A statically linked executable without `PT_DYNAMIC`.
    Static(StaticExec<D, Arch>),
}

impl<D, Arch: RelocationArch> Debug for RawExec<D, Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawExec")
            .field("name", &self.name())
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch> RawExec<D, Arch> {
    /// Creates a relocation builder for this executable image.
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), (), D, Arch> {
        Relocator::new().with_object(self)
    }

    /// Returns the name of the executable.
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

    pub fn tls_mod_id(&self) -> Option<TlsModuleId> {
        match self {
            RawExec::Dynamic(image) => image.tls_mod_id(),
            RawExec::Static(image) => image.tls_mod_id(),
        }
    }

    pub fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        match self {
            RawExec::Dynamic(image) => image.tls_tp_offset(),
            RawExec::Static(image) => image.tls_tp_offset(),
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

    /// Returns the length of the bounding runtime span covered by mapped slices.
    pub fn mapped_len(&self) -> usize {
        match self {
            RawExec::Dynamic(image) => image.mapped_len(),
            RawExec::Static(image) => image.mapped_len(),
        }
    }

    /// Returns the lowest runtime address covered by this executable's mapped slices.
    pub(crate) fn mapped_base(&self) -> usize {
        match self {
            RawExec::Dynamic(image) => image.mapped_base(),
            RawExec::Static(image) => image.mapped_base(),
        }
    }

    /// Returns whether `addr` is inside one of this executable's mapped slices.
    pub fn contains_addr(&self, addr: usize) -> bool {
        match self {
            RawExec::Dynamic(image) => image.contains_addr(addr),
            RawExec::Static(image) => image.contains_addr(addr),
        }
    }

    pub fn base(&self) -> usize {
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
#[derive(Clone, Debug)]
pub struct LoadedExec<D: 'static, Arch: RelocationArch = NativeArch> {
    /// Entry point of the executable.
    entry: RelocAddr,
    /// The relocated ELF object.
    inner: LoadedExecInner<D, Arch>,
}

#[derive(Clone, Debug)]
enum LoadedExecInner<D: 'static, Arch: RelocationArch = NativeArch> {
    Dynamic(LoadedCore<D, Arch>),
    Static(StaticExec<D, Arch>),
}

impl<D: 'static, Arch: RelocationArch> LoadedExec<D, Arch> {
    /// Returns the entry point of the executable.
    #[inline]
    pub fn entry(&self) -> usize {
        self.entry.into_inner()
    }

    /// Returns the name of the executable.
    #[inline]
    pub fn name(&self) -> &str {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => unsafe { module.core_ref().name() },
            LoadedExecInner::Static(static_image) => &static_image.inner.name,
        }
    }

    /// Returns the length of the bounding runtime span covered by mapped slices.
    pub fn mapped_len(&self) -> usize {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => unsafe { module.core_ref().mapped_len() },
            LoadedExecInner::Static(static_image) => static_image.mapped_len(),
        }
    }

    /// Returns whether `addr` is inside one of this executable's mapped slices.
    pub fn contains_addr(&self, addr: usize) -> bool {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.contains_addr(addr),
            LoadedExecInner::Static(static_image) => static_image.contains_addr(addr),
        }
    }

    /// Returns a reference to the user-defined data associated with this executable.
    pub fn user_data(&self) -> &D {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => unsafe { &module.core_ref().user_data() },
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
    pub fn core_ref(&self) -> Option<&LoadedCore<D, Arch>> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => Some(module),
            LoadedExecInner::Static(_) => None,
        }
    }

    pub fn tls_mod_id(&self) -> Option<TlsModuleId> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.core.tls_mod_id(),
            LoadedExecInner::Static(static_image) => static_image.tls_mod_id(),
        }
    }

    pub fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.core.tls_tp_offset(),
            LoadedExecInner::Static(static_image) => static_image.tls_tp_offset(),
        }
    }
}

impl<D, Arch: RelocationArch> StaticExec<D, Arch> {
    pub(crate) fn from_builder<'hook, H, M, Tls>(
        mut builder: ImageBuilder<'hook, H, M, Tls, D, Arch::Layout>,
        phdrs: &[ElfPhdr<Arch::Layout>],
    ) -> Result<Self>
    where
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
    {
        // Parse all program headers
        builder.parse_phdrs(phdrs)?;

        let entry = RelocAddr::new(builder.ehdr.e_entry());
        let (tls_mod_id, tls_tp_offset) = if let Some(info) = &builder.tls_info {
            // Static executables always use static TLS if PT_TLS is present.
            let (mod_id, offset) = Tls::register_static(info)?;
            (Some(mod_id), Some(offset))
        } else {
            (None, None)
        };

        let static_inner = StaticExecInner {
            entry,
            name: builder.name,
            user_data: builder.user_data,
            segments: builder.segments,
            phdrs: if phdrs.is_empty() {
                None
            } else {
                Some(phdrs.to_vec())
            },
            tls_mod_id,
            tls_tp_offset,
        };
        Ok(StaticExec {
            inner: Arc::new(static_inner),
        })
    }
}

impl<D: 'static, Arch: RelocationArch> RawExec<D, Arch> {
    pub(crate) fn from_builder<'hook, H, M, Tls>(
        builder: ImageBuilder<'hook, H, M, Tls, D, Arch::Layout>,
        phdrs: &[ElfPhdr<Arch::Layout>],
        has_dynamic: bool,
    ) -> Result<Self>
    where
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
    {
        if has_dynamic {
            Ok(Self::Dynamic(RawDynamic::from_builder(builder, phdrs)?))
        } else {
            Ok(Self::Static(StaticExec::from_builder(builder, phdrs)?))
        }
    }
}
