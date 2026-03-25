use crate::sync::Arc;
/// Executable file handling
///
/// This module provides functionality for working with executable ELF files
/// that have been loaded but not yet relocated. It includes support for
/// synchronous loading of executable files.
use crate::{
    Result,
    elf::ElfPhdr,
    image::{DynamicImage, LoadedCore},
    loader::{ImageBuilder, LoadHook},
    os::Mmap,
    relocation::{
        BindingOptions, RelocAddr, Relocatable, RelocationHandler, Relocator, SupportLazy,
        SymbolLookup,
    },
    segment::ElfSegments,
    tls::TlsResolver,
};
use alloc::{string::String, vec::Vec};
use core::fmt::Debug;

#[derive(Clone)]
pub(crate) struct StaticImage<D> {
    inner: Arc<StaticImageInner<D>>,
}

impl<D> Debug for StaticImage<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticImage")
            .field("name", &self.inner.name)
            .finish()
    }
}

impl<D> StaticImage<D> {
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

    pub fn base(&self) -> usize {
        self.inner.segments.base()
    }
}

struct StaticImageInner<D> {
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

    fn relocate<PreS, PostS, LazyS, PreH, PostH>(
        self,
        scope: Vec<LoadedCore<D>>,
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
        binding: BindingOptions<LazyS>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        match self.inner {
            ExecImageInner::Dynamic(image) => {
                let entry = image.entry_addr();
                let inner = image.relocate_impl(
                    scope,
                    pre_find,
                    post_find,
                    pre_handler,
                    post_handler,
                    binding,
                )?;
                Ok(LoadedExec {
                    entry,
                    inner: LoadedExecInner::Dynamic(inner),
                })
            }
            ExecImageInner::Static(image) => Ok(LoadedExec {
                entry: image.entry_addr(),
                inner: LoadedExecInner::Static(image),
            }),
        }
    }
}

/// An unrelocated executable file.
///
/// This structure represents an executable ELF file that has been loaded
/// into memory but has not yet undergone relocation. It contains all the
/// necessary information to perform relocation and prepare the executable
/// for execution.
pub struct RawExec<D>
where
    D: 'static,
{
    pub(crate) inner: ExecImageInner<D>,
}

impl<D: 'static> SupportLazy for RawExec<D> {}

pub(crate) enum ExecImageInner<D>
where
    D: 'static,
{
    /// The common part containing basic ELF object information.
    Dynamic(DynamicImage<D>),
    Static(StaticImage<D>),
}

impl<D> Debug for RawExec<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawExec")
            .field("name", &self.name())
            .finish()
    }
}

impl<D: 'static> RawExec<D> {
    /// Creates a builder for relocating the executable.
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), D> {
        Relocator::new(self)
    }

    /// Returns the name of the executable.
    pub fn name(&self) -> &str {
        match &self.inner {
            ExecImageInner::Dynamic(image) => image.name(),
            ExecImageInner::Static(image) => image.name(),
        }
    }

    /// Returns the entry point of the executable.
    pub fn entry(&self) -> usize {
        match &self.inner {
            ExecImageInner::Dynamic(image) => image.entry(),
            ExecImageInner::Static(image) => image.entry(),
        }
    }

    pub fn tls_mod_id(&self) -> Option<usize> {
        match &self.inner {
            ExecImageInner::Dynamic(image) => image.tls_mod_id(),
            ExecImageInner::Static(image) => image.tls_mod_id(),
        }
    }

    pub fn tls_tp_offset(&self) -> Option<isize> {
        match &self.inner {
            ExecImageInner::Dynamic(image) => image.tls_tp_offset(),
            ExecImageInner::Static(image) => image.tls_tp_offset(),
        }
    }

    /// Returns the PT_INTERP value.
    pub fn interp(&self) -> Option<&str> {
        match &self.inner {
            ExecImageInner::Dynamic(image) => image.interp(),
            ExecImageInner::Static(_) => None,
        }
    }

    /// Returns the program headers of the executable.
    pub fn phdrs(&self) -> Option<&[ElfPhdr]> {
        match &self.inner {
            ExecImageInner::Dynamic(image) => Some(image.phdrs()),
            ExecImageInner::Static(image) => image.inner.phdrs.as_deref(),
        }
    }

    /// Returns the total length of memory that will be occupied by the executable after relocation.
    pub fn mapped_len(&self) -> usize {
        match &self.inner {
            ExecImageInner::Dynamic(image) => image.mapped_len(),
            ExecImageInner::Static(image) => image.inner.segments.len(),
        }
    }

    pub fn base(&self) -> usize {
        match &self.inner {
            ExecImageInner::Dynamic(image) => image.base(),
            ExecImageInner::Static(image) => image.base(),
        }
    }
}

/// An executable file that has been relocated.
///
/// This structure represents an executable ELF file that has been loaded
/// and relocated in memory, making it ready for execution. It contains
/// the entry point and other information needed to run the executable.
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
    Static(StaticImage<D>),
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

    /// Returns the total length of memory occupied by the executable.
    pub fn mapped_len(&self) -> usize {
        match &self.inner {
            LoadedExecInner::Dynamic(module) => unsafe { module.core_ref().mapped_len() },
            LoadedExecInner::Static(static_image) => static_image.inner.segments.len(),
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

impl<D> StaticImage<D> {
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

        let entry = RelocAddr::new(builder.ehdr.e_entry as usize);
        let (tls_mod_id, tls_tp_offset) = if let Some(info) = &builder.tls_info {
            // Static executables always use static TLS if PT_TLS is present.
            let (mod_id, offset) = Tls::register_static(info)?;
            (Some(mod_id), Some(offset))
        } else {
            (None, None)
        };

        let static_inner = StaticImageInner {
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
        Ok(StaticImage {
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
        Ok(Self {
            inner: if has_dynamic {
                ExecImageInner::Dynamic(DynamicImage::from_builder(builder, phdrs)?)
            } else {
                ExecImageInner::Static(StaticImage::from_builder(builder, phdrs)?)
            },
        })
    }
}
