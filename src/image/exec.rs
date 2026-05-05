//! Executable image types.
//!
//! Use [`RawExec`] for an executable that has been mapped but not yet relocated,
//! and [`LoadedExec`] for the final executable form produced by relocation.

use crate::sync::Arc;
use crate::{
    Result,
    elf::ElfPhdr,
    image::{LoadedCore, RawDynamic},
    loader::{ImageBuilder, LoadHook},
    os::Mmap,
    relocation::{
        RelocAddr, Relocatable, RelocateArgs, RelocationHandler, Relocator, SymbolLookup,
    },
    segment::ElfSegments,
    tls::TlsResolver,
};
use alloc::{string::String, vec::Vec};
use core::fmt::Debug;

/// A mapped static executable.
///
/// Static executables do not have `PT_DYNAMIC`, so they are ready to run after
/// mapping and any static TLS setup performed by the loader.
#[derive(Clone)]
pub struct StaticExec<D> {
    inner: Arc<StaticExecInner<D>>,
}

impl<D> Debug for StaticExec<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticExec")
            .field("name", &self.inner.name)
            .finish()
    }
}

impl<D> StaticExec<D> {
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn entry(&self) -> usize {
        self.entry_addr().into_inner()
    }

    pub(crate) fn entry_addr(&self) -> RelocAddr {
        self.inner.entry
    }

    pub fn tls_mod_id(&self) -> Option<usize> {
        self.inner.tls_mod_id
    }

    pub fn tls_tp_offset(&self) -> Option<isize> {
        self.inner.tls_tp_offset
    }

    pub fn user_data(&self) -> &D {
        &self.inner.user_data
    }

    pub fn phdrs(&self) -> Option<&[ElfPhdr]> {
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

struct StaticExecInner<D> {
    /// File name of the ELF object
    name: String,

    /// Entry point of the executable
    entry: RelocAddr,

    /// User-defined data
    user_data: D,

    /// Memory segments
    segments: ElfSegments,

    /// Program headers
    phdrs: Option<Vec<ElfPhdr>>,

    /// TLS module ID
    tls_mod_id: Option<usize>,

    /// TLS thread pointer offset
    tls_tp_offset: Option<isize>,
}

impl<D: 'static> Relocatable<D> for RawExec<D> {
    type Output = LoadedExec<D>;

    fn relocate<PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyPreS: SymbolLookup + Send + Sync + 'static,
        LazyPostS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
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
impl<D: 'static> crate::relocation::SupportLazy for RawExec<D> {}

/// A mapped but unrelocated executable image.
///
/// Values of this type are returned by [`crate::Loader::load_exec`]. They may
/// represent either a dynamic executable that still needs relocation or a
/// static executable that is already ready to run.
pub enum RawExec<D>
where
    D: 'static,
{
    /// A dynamically linked executable with `PT_DYNAMIC`.
    Dynamic(RawDynamic<D>),

    /// A statically linked executable without `PT_DYNAMIC`.
    Static(StaticExec<D>),
}

impl<D> Debug for RawExec<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawExec")
            .field("name", &self.name())
            .finish()
    }
}

impl<D: 'static> RawExec<D> {
    /// Creates a relocation builder for this executable image.
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), (), D> {
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

    pub fn tls_mod_id(&self) -> Option<usize> {
        match self {
            RawExec::Dynamic(image) => image.tls_mod_id(),
            RawExec::Static(image) => image.tls_mod_id(),
        }
    }

    pub fn tls_tp_offset(&self) -> Option<isize> {
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
    pub fn phdrs(&self) -> Option<&[ElfPhdr]> {
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
pub struct LoadedExec<D> {
    /// Entry point of the executable.
    entry: RelocAddr,
    /// The relocated ELF object.
    inner: LoadedExecInner<D>,
}

#[derive(Clone, Debug)]
enum LoadedExecInner<D> {
    Dynamic(LoadedCore<D>),
    Static(StaticExec<D>),
}

impl<D> LoadedExec<D> {
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
    pub fn core_ref(&self) -> Option<&LoadedCore<D>> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => Some(module),
            LoadedExecInner::Static(_) => None,
        }
    }

    pub fn tls_mod_id(&self) -> Option<usize> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.core.tls_mod_id(),
            LoadedExecInner::Static(static_image) => static_image.tls_mod_id(),
        }
    }

    pub fn tls_tp_offset(&self) -> Option<isize> {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => module.core.tls_tp_offset(),
            LoadedExecInner::Static(static_image) => static_image.tls_tp_offset(),
        }
    }
}

impl<D> StaticExec<D> {
    pub(crate) fn from_builder<'hook, H, M, Tls>(
        mut builder: ImageBuilder<'hook, H, M, Tls, D>,
        phdrs: &[ElfPhdr],
    ) -> Result<Self>
    where
        M: Mmap,
        H: LoadHook,
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

impl<D: 'static> RawExec<D> {
    pub(crate) fn from_builder<'hook, H, M, Tls>(
        builder: ImageBuilder<'hook, H, M, Tls, D>,
        phdrs: &[ElfPhdr],
        has_dynamic: bool,
    ) -> Result<Self>
    where
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        if has_dynamic {
            Ok(Self::Dynamic(RawDynamic::from_builder(builder, phdrs)?))
        } else {
            Ok(Self::Static(StaticExec::from_builder(builder, phdrs)?))
        }
    }
}
