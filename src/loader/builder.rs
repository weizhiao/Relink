use super::{DynLifecycleHandler, LoadHook, LoadHookContext, LoaderInner};
use crate::{
    ParsePhdrError, Result,
    elf::{ElfDyn, ElfHeader, ElfPhdr, ElfPhdrs, ElfProgramType},
    input::ElfReader,
    os::Mmap,
    segment::{ELFRelro, ElfSegments, SegmentBuilder, program::ProgramSegments},
    tls::{TlsInfo, TlsResolver},
};
use alloc::{borrow::ToOwned, boxed::Box, string::String, vec::Vec};
use core::{ffi::c_char, marker::PhantomData, ptr::NonNull};

/// Builder for creating relocated ELF objects
///
/// This structure is used internally during the loading process to collect
/// and organize the various components of a relocated ELF file before
/// building the final loaded image.
pub(crate) struct ImageBuilder<'hook, H, M, Tls, D = ()>
where
    H: LoadHook,
    M: Mmap,
    Tls: TlsResolver,
{
    /// Hook function for processing program headers (always present)
    hook: &'hook mut H,

    /// Mapped program headers
    phdr_mmap: Option<&'static [ElfPhdr]>,

    /// Name of the ELF file
    pub(crate) name: String,

    /// ELF header
    pub(crate) ehdr: ElfHeader,

    /// GNU_RELRO segment information
    pub(crate) relro: Option<ELFRelro>,

    /// Pointer to the dynamic section
    pub(crate) dynamic_ptr: Option<NonNull<ElfDyn>>,

    /// TLS information
    pub(crate) tls_info: Option<TlsInfo>,

    /// Whether to use static TLS
    pub(crate) static_tls: bool,

    /// User-defined data
    pub(crate) user_data: D,

    /// Memory segments
    pub(crate) segments: ElfSegments,

    /// Initialization function handler
    pub(crate) init_fn: DynLifecycleHandler,

    /// Finalization function handler
    pub(crate) fini_fn: DynLifecycleHandler,

    /// Pointer to the interpreter path (PT_INTERP)
    pub(crate) interp: Option<NonNull<c_char>>,

    /// Pointer to the .eh_frame_hdr section (PT_GNU_EH_FRAME)
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,

    /// Phantom data to maintain Mmap type information
    _marker: PhantomData<(M, Tls)>,
}

pub(crate) struct ScanBuilder<D = ()>
where
    D: 'static,
{
    pub(crate) name: String,
    pub(crate) ehdr: ElfHeader,
    pub(crate) phdrs: Box<[ElfPhdr]>,
    pub(crate) reader: Box<dyn ElfReader + 'static>,
    pub(crate) user_data: D,
}

impl<D> ScanBuilder<D>
where
    D: 'static,
{
    #[inline]
    pub(crate) fn new(
        name: String,
        ehdr: ElfHeader,
        phdrs: Box<[ElfPhdr]>,
        reader: Box<dyn ElfReader + 'static>,
        user_data: D,
    ) -> Self {
        Self {
            name,
            ehdr,
            phdrs,
            reader,
            user_data,
        }
    }
}

impl<'hook, H, M, Tls, D> ImageBuilder<'hook, H, M, Tls, D>
where
    H: LoadHook,
    Tls: TlsResolver,
    M: Mmap,
{
    /// Create a new [`ImageBuilder`].
    ///
    /// # Arguments
    /// * `hook` - Hook function for processing program headers
    /// * `segments` - Memory segments of the ELF file
    /// * `name` - Name of the ELF file
    /// * `ehdr` - ELF header
    /// * `init_fn` - Initialization function handler
    /// * `fini_fn` - Finalization function handler
    ///
    pub(crate) fn new(
        hook: &'hook mut H,
        segments: ElfSegments,
        name: String,
        ehdr: ElfHeader,
        init_fn: DynLifecycleHandler,
        fini_fn: DynLifecycleHandler,
        static_tls: bool,
        user_data: D,
    ) -> Self {
        Self {
            hook,
            phdr_mmap: None,
            name,
            ehdr,
            relro: None,
            dynamic_ptr: None,
            tls_info: None,
            static_tls,
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
    pub(crate) fn parse_phdr(&mut self, phdr: &ElfPhdr) -> Result<()> {
        let ctx = LoadHookContext::new(&self.name, phdr, &self.segments);
        self.hook.call(&ctx)?;

        match phdr.program_type() {
            ElfProgramType::DYNAMIC => {
                self.dynamic_ptr = Some(
                    NonNull::new(self.segments.get_mut_ptr(phdr.p_vaddr()))
                        .ok_or(ParsePhdrError::MalformedProgramHeaders)?,
                )
            }
            ElfProgramType::GNU_RELRO => {
                self.relro = Some(ELFRelro::new::<M>(phdr, self.segments.base_addr()))
            }
            ElfProgramType::PHDR => {
                self.phdr_mmap = Some(
                    self.segments
                        .get_slice::<ElfPhdr>(phdr.p_vaddr(), phdr.p_memsz()),
                );
            }
            ElfProgramType::INTERP => {
                self.interp = Some(
                    NonNull::new(self.segments.get_mut_ptr(phdr.p_vaddr()))
                        .ok_or(ParsePhdrError::MalformedProgramHeaders)?,
                );
            }
            ElfProgramType::GNU_EH_FRAME => {
                self.eh_frame_hdr = Some(
                    NonNull::new(self.segments.get_mut_ptr(phdr.p_vaddr()))
                        .ok_or(ParsePhdrError::MalformedProgramHeaders)?,
                );
            }
            ElfProgramType::TLS => {
                let tls_image = self
                    .segments
                    .get_slice::<u8>(phdr.p_vaddr(), phdr.p_filesz());
                self.tls_info = Some(TlsInfo::new(phdr, tls_image));
            }
            _ => {}
        };
        Ok(())
    }

    /// Parse all program headers and collect the builder state they describe.
    pub(crate) fn parse_phdrs(&mut self, phdrs: &[ElfPhdr]) -> Result<()> {
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
    pub(crate) fn create_phdrs(&self, phdrs: &[ElfPhdr]) -> ElfPhdrs {
        let (phdr_start, phdr_end) = self.ehdr.phdr_range();
        let phdr_size = phdr_end - phdr_start;

        // Get mapped program headers or create them from loaded segments
        self.phdr_mmap
            .or_else(|| {
                phdrs
                    .iter()
                    .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
                    .find_map(|phdr| {
                        let seg_start = phdr.p_offset();
                        let seg_end = seg_start + phdr.p_filesz();
                        if seg_start <= phdr_start && phdr_end <= seg_end {
                            return Some(self.segments.get_slice::<ElfPhdr>(
                                phdr.p_vaddr() + (phdr_start - seg_start),
                                phdr_size,
                            ));
                        }
                        None
                    })
            })
            .map(ElfPhdrs::Mmap)
            .unwrap_or_else(|| ElfPhdrs::Vec(Vec::from(phdrs)))
    }
}

impl<H, D> LoaderInner<H, D>
where
    H: LoadHook,
    D: 'static,
{
    pub(crate) fn lifecycle_handlers(&self) -> (DynLifecycleHandler, DynLifecycleHandler) {
        (self.init_fn.clone(), self.fini_fn.clone())
    }

    #[inline]
    pub(crate) fn force_static_tls(&self) -> bool {
        self.force_static_tls
    }

    #[inline]
    pub(crate) fn initialize_dylib(&mut self, dylib: &mut crate::image::RawDylib<D>) -> Result<()> {
        (self.dylib_initializer)(dylib)
    }
}

impl<H, D> LoaderInner<H, D>
where
    H: LoadHook,
    D: Default + 'static,
{
    pub(crate) fn create_builder<M, Tls>(
        &mut self,
        ehdr: ElfHeader,
        phdrs: &[ElfPhdr],
        mut object: impl crate::input::ElfReader,
    ) -> Result<ImageBuilder<'_, H, M, Tls, D>>
    where
        M: Mmap,
        Tls: TlsResolver,
    {
        let name = object.file_name().to_owned();
        let (init_fn, fini_fn) = self.lifecycle_handlers();
        let mut phdr_segments =
            ProgramSegments::new(phdrs, ehdr.is_dylib(), object.as_fd().is_some());
        let segments = phdr_segments.load_segments::<M>(&mut object)?;
        phdr_segments.mprotect::<M>()?;

        Ok(ImageBuilder::new(
            &mut self.hook,
            segments,
            name,
            ehdr,
            init_fn,
            fini_fn,
            self.force_static_tls,
            D::default(),
        ))
    }

    pub(crate) fn create_scan_builder(
        &self,
        ehdr: ElfHeader,
        phdrs: &[ElfPhdr],
        object: impl ElfReader + 'static,
    ) -> ScanBuilder<D> {
        let name = object.file_name().to_owned();

        ScanBuilder::new(name, ehdr, phdrs.into(), Box::new(object), D::default())
    }
}
