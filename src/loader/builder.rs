use super::{DynLifecycleHandler, LoadHook, LoadHookContext, LoaderInner};
use crate::{
    ByteRepr, ParsePhdrError, Result,
    elf::{ElfDyn, ElfHeader, ElfLayout, ElfPhdr, ElfPhdrs, ElfProgramType, NativeElfLayout},
    input::{ElfReader, PathBuf},
    os::{MappedView, Mapper},
    segment::{ELFRelro, ElfSegments, SegmentBuilder, program::ProgramSegments},
    tls::{TlsInfo, TlsResolver},
};
use alloc::{boxed::Box, vec::Vec};
use core::{marker::PhantomData, ptr::NonNull};

/// Builder for creating relocated ELF objects
///
/// This structure is used internally during the loading process to collect
/// and organize the various components of a relocated ELF file before
/// building the final loaded image.
pub(crate) struct ImageBuilder<'hook, H, Tls, D = (), L: ElfLayout = NativeElfLayout>
where
    H: LoadHook<L>,
    Tls: TlsResolver,
{
    /// Hook function for processing program headers (always present)
    hook: &'hook mut H,

    /// Loader source path or caller-provided source identifier.
    pub(crate) path: PathBuf,

    /// ELF header
    pub(crate) ehdr: ElfHeader<L>,

    /// GNU_RELRO segment information
    pub(crate) relro: Option<ELFRelro>,

    /// Dynamic section entries
    pub(crate) dynamic: Option<MappedView<ElfDyn<L>>>,

    /// TLS information
    pub(crate) tls_info: Option<TlsInfo>,

    /// Whether to use static TLS
    pub(crate) static_tls: bool,

    /// Page size used for segment layout.
    page_size: usize,

    /// Mapping backend used by protections created from this builder.
    mapper: Mapper,

    /// User-defined data
    pub(crate) user_data: D,

    /// Memory segments
    pub(crate) segments: ElfSegments,

    /// Initialization function handler
    pub(crate) init_fn: DynLifecycleHandler,

    /// Finalization function handler
    pub(crate) fini_fn: DynLifecycleHandler,

    /// Interpreter path (PT_INTERP)
    pub(crate) interp: Option<&'static str>,

    /// Pointer to the .eh_frame_hdr section (PT_GNU_EH_FRAME)
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,

    /// Phantom data to maintain TLS type information.
    _marker: PhantomData<(Tls, L)>,
}

pub(crate) struct ScanBuilder<L: ElfLayout = NativeElfLayout> {
    pub(crate) path: PathBuf,
    pub(crate) ehdr: ElfHeader<L>,
    pub(crate) phdrs: Box<[ElfPhdr<L>]>,
    pub(crate) reader: Box<dyn ElfReader + 'static>,
}

impl<L: ElfLayout> ScanBuilder<L> {
    #[inline]
    pub(crate) fn new(
        path: PathBuf,
        ehdr: ElfHeader<L>,
        phdrs: Box<[ElfPhdr<L>]>,
        reader: Box<dyn ElfReader + 'static>,
    ) -> Self {
        Self {
            path,
            ehdr,
            phdrs,
            reader,
        }
    }
}

impl<'hook, H, Tls, D, L> ImageBuilder<'hook, H, Tls, D, L>
where
    H: LoadHook<L>,
    Tls: TlsResolver,
    L: ElfLayout,
{
    /// Create a new [`ImageBuilder`].
    ///
    /// # Arguments
    /// * `hook` - Hook function for processing program headers
    /// * `segments` - Memory segments of the ELF file
    /// * `path` - Loader source path or caller-provided source identifier
    /// * `ehdr` - ELF header
    /// * `init_fn` - Initialization function handler
    /// * `fini_fn` - Finalization function handler
    ///
    pub(crate) fn new(
        hook: &'hook mut H,
        segments: ElfSegments,
        path: PathBuf,
        ehdr: ElfHeader<L>,
        init_fn: DynLifecycleHandler,
        fini_fn: DynLifecycleHandler,
        static_tls: bool,
        page_size: usize,
        mapper: Mapper,
        user_data: D,
    ) -> Self {
        Self {
            hook,
            path,
            ehdr,
            relro: None,
            dynamic: None,
            tls_info: None,
            static_tls,
            page_size,
            mapper,
            segments,
            user_data,
            init_fn,
            fini_fn,
            interp: None,
            eh_frame_hdr: None,
            _marker: PhantomData,
        }
    }

    /// Parse a program header and extract relevant information.
    pub(crate) fn parse_phdr(&mut self, phdr: &ElfPhdr<L>) -> Result<()> {
        let ctx = LoadHookContext::new(self.path.as_path(), phdr, &self.segments);
        self.hook.call(&ctx)?;

        match phdr.program_type() {
            ElfProgramType::DYNAMIC => {
                self.dynamic = Some(self.read_segment_view::<ElfDyn<L>>(
                    phdr,
                    "PT_DYNAMIC is not directly readable from mapped segments",
                )?)
            }
            ElfProgramType::GNU_RELRO => {
                self.relro = Some(ELFRelro::new(
                    phdr,
                    self.segments.base_addr(),
                    self.page_size,
                    self.mapper.clone(),
                ))
            }
            ElfProgramType::PHDR => {}
            ElfProgramType::INTERP => {
                self.interp = Some(self.read_interp(phdr)?);
            }
            ElfProgramType::GNU_EH_FRAME => {
                self.eh_frame_hdr = Some(self.borrowed_segment_ptr::<u8>(
                    phdr,
                    "PT_GNU_EH_FRAME is not directly readable from mapped segments",
                )?);
            }
            ElfProgramType::TLS => {
                let tls_image = self
                    .segments
                    .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())?
                    .ok_or_else(|| ParsePhdrError::malformed("PT_TLS image is malformed"))?;
                self.tls_info = Some(TlsInfo::new(phdr, tls_image.as_slice()));
            }
            _ => {}
        };
        Ok(())
    }

    #[inline]
    fn read_segment_view<T: ByteRepr + 'static>(
        &self,
        phdr: &ElfPhdr<L>,
        detail: &'static str,
    ) -> Result<MappedView<T>> {
        let view = self
            .segments
            .read_view::<T>(phdr.p_vaddr(), phdr.p_filesz())?
            .ok_or_else(|| ParsePhdrError::malformed(detail))?;
        if view.is_empty() {
            return Err(ParsePhdrError::malformed(detail).into());
        }
        Ok(view)
    }

    #[inline]
    fn borrowed_segment_ptr<T: ByteRepr + 'static>(
        &self,
        phdr: &ElfPhdr<L>,
        detail: &'static str,
    ) -> Result<NonNull<T>> {
        self.segments
            .borrowed_ptr::<T>(phdr.p_vaddr(), phdr.p_filesz())?
            .ok_or_else(|| ParsePhdrError::malformed(detail).into())
    }

    fn read_interp(&self, phdr: &ElfPhdr<L>) -> Result<&'static str> {
        let view = self
            .segments
            .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())?
            .ok_or_else(|| {
                ParsePhdrError::malformed("PT_INTERP is not directly readable from mapped segments")
            })?;
        let bytes = view.as_slice();
        let Some(nul) = bytes.iter().position(|byte| *byte == 0) else {
            return Err(ParsePhdrError::malformed("PT_INTERP is missing a NUL terminator").into());
        };
        if nul == 0 {
            return Err(ParsePhdrError::malformed("PT_INTERP is empty").into());
        }
        core::str::from_utf8(&bytes[..nul])
            .map_err(|_| ParsePhdrError::InvalidUtf8 { field: "PT_INTERP" }.into())
    }

    /// Parse all program headers and collect the builder state they describe.
    pub(crate) fn parse_phdrs(&mut self, phdrs: &[ElfPhdr<L>]) -> Result<()> {
        for phdr in phdrs {
            self.parse_phdr(phdr)?;
        }
        Ok(())
    }

    /// Create program headers from the parsed data
    ///
    /// This method creates the appropriate program header representation
    /// based on whether they are mapped in memory or need to be stored
    /// in a vector.
    ///
    /// # Arguments
    /// * `phdrs` - Slice of program headers
    ///
    /// # Returns
    /// An ElfPhdrs enum containing either mapped or vector-based headers
    pub(crate) fn create_phdrs(&self, phdrs: &[ElfPhdr<L>]) -> Result<ElfPhdrs<L>> {
        for phdr in phdrs {
            if phdr.program_type() != ElfProgramType::PHDR {
                continue;
            }
            if let Some(mapped) = self
                .segments
                .read_view::<ElfPhdr<L>>(phdr.p_vaddr(), phdr.p_memsz())?
            {
                return Ok(ElfPhdrs::Mapped(mapped));
            }
        }

        let (phdr_start, phdr_end) = self.ehdr.phdr_range();
        let phdr_size = phdr_end - phdr_start;
        for phdr in phdrs {
            if phdr.program_type() != ElfProgramType::LOAD {
                continue;
            }
            let seg_start = phdr.p_offset();
            let Some(seg_end) = seg_start.checked_add(phdr.p_filesz()) else {
                continue;
            };
            if seg_start <= phdr_start && phdr_end <= seg_end {
                let Some(phdr_vaddr) = phdr.p_vaddr().checked_add(phdr_start - seg_start) else {
                    continue;
                };
                if let Some(mapped) = self
                    .segments
                    .read_view::<ElfPhdr<L>>(phdr_vaddr, phdr_size)?
                {
                    return Ok(ElfPhdrs::Mapped(mapped));
                }
            }
        }

        Ok(ElfPhdrs::Vec(Vec::from(phdrs)))
    }
}

impl<H, D, Arch> LoaderInner<H, D, Arch>
where
    H: LoadHook<Arch::Layout>,
    D: 'static,
    Arch: crate::relocation::RelocationArch,
{
    pub(crate) fn create_builder<Tls>(
        &mut self,
        ehdr: ElfHeader<Arch::Layout>,
        phdrs: &[ElfPhdr<Arch::Layout>],
        mut object: impl ElfReader,
        user_data: D,
    ) -> Result<ImageBuilder<'_, H, Tls, D, Arch::Layout>>
    where
        Tls: TlsResolver,
    {
        let path = PathBuf::from(object.path());
        let (init_fn, fini_fn) = self.lifecycle_handlers();
        let mapper = self.mapper();
        let page_size = self.page_size()?.bytes();
        let mut phdr_segments =
            ProgramSegments::new(phdrs, ehdr.is_dylib(), object.as_fd().is_some(), page_size);
        let segments = phdr_segments.load_segments(mapper.clone(), &mut object)?;
        phdr_segments.mprotect(mapper.as_ref())?;

        Ok(ImageBuilder::new(
            &mut self.hook,
            segments,
            path,
            ehdr,
            init_fn,
            fini_fn,
            self.force_static_tls,
            page_size,
            mapper,
            user_data,
        ))
    }

    pub(crate) fn create_scan_builder(
        &self,
        ehdr: ElfHeader<Arch::Layout>,
        phdrs: &[ElfPhdr<Arch::Layout>],
        object: impl ElfReader + 'static,
    ) -> ScanBuilder<Arch::Layout> {
        let path = PathBuf::from(object.path());

        ScanBuilder::new(path, ehdr, phdrs.into(), Box::new(object))
    }
}
