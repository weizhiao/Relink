/// Executable file handling
///
/// This module provides functionality for working with executable ELF files
/// that have been loaded but not yet relocated. It includes support for
/// synchronous loading of executable files.
use crate::{
    LoadHook, Loader, Result,
    elf::ElfPhdr,
    image::{DynamicImage, ImageBuilder, LoadedCore},
    input::{ElfReader, IntoElfReader},
    os::Mmap,
    parse_ehdr_error,
    relocation::{Relocatable, RelocationHandler, Relocator, SymbolLookup},
    segment::ElfSegments,
    tls::TlsResolver,
};
use alloc::{string::String, vec::Vec};
use core::fmt::Debug;
use elf::abi::PT_DYNAMIC;

#[cfg(not(feature = "portable-atomic"))]
use alloc::sync::Arc;
#[cfg(feature = "portable-atomic")]
use portable_atomic_util::Arc;

#[derive(Clone)]
pub(crate) struct StaticImage<D> {
    pub(crate) inner: Arc<StaticImageInner<D>>,
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
        self.inner.entry
    }

    pub fn tls_mod_id(&self) -> Option<usize> {
        self.inner.tls_mod_id
    }

    pub fn tls_tp_offset(&self) -> Option<isize> {
        self.inner.tls_tp_offset
    }
}

pub(crate) struct StaticImageInner<D> {
    /// File name of the ELF object
    pub(crate) name: String,

    pub(crate) entry: usize,

    /// User-defined data
    pub(crate) user_data: D,

    /// Memory segments
    pub(crate) segments: ElfSegments,

    /// TLS module ID
    pub(crate) tls_mod_id: Option<usize>,

    /// TLS thread pointer offset
    pub(crate) tls_tp_offset: Option<isize>,
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
        lazy: Option<bool>,
        lazy_scope: Option<LazyS>,
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
                let entry = image.entry();
                let inner = image.relocate_impl(
                    scope,
                    pre_find,
                    post_find,
                    pre_handler,
                    post_handler,
                    lazy,
                    lazy_scope,
                )?;
                Ok(LoadedExec {
                    entry,
                    inner: LoadedExecInner::Dynamic(inner),
                })
            }
            ExecImageInner::Static(image) => Ok(LoadedExec {
                entry: image.entry(),
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

pub(crate) enum ExecImageInner<D>
where
    D: 'static,
{
    /// The common part containing basic ELF object information.
    Dynamic(DynamicImage<D>),
    Static(StaticImage<D>),
}

impl<D> Debug for RawExec<D> {
    /// Formats the [`RawExec`] for debugging purposes.
    ///
    /// This implementation provides a debug representation that includes
    /// the executable name.
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

    /// Returns the total length of memory that will be occupied by the executable after relocation.
    pub fn mapped_len(&self) -> usize {
        match &self.inner {
            ExecImageInner::Dynamic(image) => image.mapped_len(),
            ExecImageInner::Static(image) => image.inner.segments.len(),
        }
    }
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook<D>,
    D: Default,
    Tls: TlsResolver,
{
    /// Loads an executable file into memory.
    ///
    /// This method loads an executable ELF file into memory and prepares it
    /// for relocation. The file is validated to ensure it is indeed an
    /// executable (either a standard executable or a position-independent executable).
    ///
    /// # Arguments
    /// * `object` - The ELF object to load as an executable.
    ///
    /// # Returns
    /// * `Ok(RawExec)` - The loaded executable.
    /// * `Err(Error)` - If loading fails.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, input::ElfBinary};
    ///
    /// let mut loader = Loader::new();
    /// let bytes = &[]; // ELF executable bytes
    /// let exec = loader.load_exec(ElfBinary::new("my_exec", bytes)).unwrap();
    /// ```
    pub fn load_exec<'a, I>(&mut self, input: I) -> Result<RawExec<D>>
    where
        I: IntoElfReader<'a>,
    {
        let object = input.into_reader()?;
        self.load_exec_impl(object)
    }

    pub(crate) fn load_exec_impl(&mut self, mut object: impl ElfReader) -> Result<RawExec<D>> {
        // Prepare and validate the ELF header
        let ehdr = self.buf.prepare_ehdr(&mut object)?;

        // Ensure the file is actually an executable
        if !ehdr.is_executable() {
            return Err(parse_ehdr_error("file type mismatch"));
        }

        let phdrs = self.buf.prepare_phdrs(&ehdr, &mut object)?.to_vec();
        let has_dynamic = phdrs.iter().any(|phdr| phdr.p_type == PT_DYNAMIC);

        if has_dynamic {
            // Load the relocated common part
            let inner = self.load_dynamic_impl(ehdr, &phdrs, object)?;
            // Wrap in RawExec and return
            Ok(RawExec {
                inner: ExecImageInner::Dynamic(inner),
            })
        } else {
            // Load as a static module without dynamic section
            let inner = self.load_static_impl(ehdr, &phdrs, object)?;
            Ok(RawExec {
                inner: ExecImageInner::Static(inner),
            })
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
    entry: usize,
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
        self.entry
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

impl<'hook, H, M, Tls, D> ImageBuilder<'hook, H, M, Tls, D>
where
    M: Mmap,
    D: Default,
    H: LoadHook<D>,
    Tls: TlsResolver,
{
    pub(crate) fn build_static(mut self, phdrs: &[ElfPhdr]) -> Result<StaticImage<D>> {
        // Parse all program headers
        for phdr in phdrs {
            self.parse_phdr(phdr)?;
        }

        let entry = self.ehdr.e_entry as usize;
        let static_inner = StaticImageInner {
            entry,
            name: self.name,
            user_data: self.user_data,
            segments: self.segments,
            tls_mod_id: self.tls_mod_id,
            tls_tp_offset: self.tls_tp_offset,
        };
        Ok(StaticImage {
            inner: Arc::new(static_inner),
        })
    }
}
