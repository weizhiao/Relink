use crate::{
    ParsePhdrError, Result,
    arch::NativeArch,
    elf::{ElfDyn, ElfHeader, ElfLayout, ElfPhdr, ElfPhdrs, ElfProgramType, NativeElfLayout},
    input::{ElfReader, PathBuf},
    memory::{MappedView, RegionAccess, VmAddr},
    relocation::RelocationArch,
    segment::{ELFRelro, ElfSegments},
    tls::{TlsInfo, TlsResolver},
};
use alloc::{boxed::Box, vec::Vec};
use core::{marker::PhantomData, ptr::NonNull};

/// Builder for creating relocated ELF objects
///
/// This structure is used internally during the loading process to collect
/// and organize the various components of a relocated ELF file before
/// building the final loaded image.
pub(crate) struct ImageBuilder<
    Tls,
    D: 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = crate::memory::HostRegion,
> where
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    /// Loader source path or caller-provided source identifier.
    pub(crate) path: PathBuf,

    /// ELF header
    pub(crate) ehdr: ElfHeader<Arch::Layout>,

    /// GNU_RELRO segment information
    pub(crate) relro: Option<ELFRelro>,

    /// Dynamic section entries
    pub(crate) dynamic: Option<MappedView<ElfDyn<Arch::Layout>>>,

    /// Runtime address of the first dynamic section entry.
    pub(crate) dynamic_addr: Option<VmAddr>,

    /// TLS information
    pub(crate) tls_info: Option<TlsInfo>,

    /// Whether to use static TLS
    pub(crate) static_tls: bool,

    /// Page size used for segment layout.
    page_size: usize,

    /// User-defined data
    pub(crate) user_data: D,

    /// Memory segments
    pub(crate) segments: ElfSegments<R>,

    /// Interpreter path (PT_INTERP)
    pub(crate) interp: Option<&'static str>,

    /// Pointer to the .eh_frame_hdr section (PT_GNU_EH_FRAME)
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,

    /// Phantom data to maintain TLS type information.
    _marker: PhantomData<(Tls, Arch)>,
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

impl<Tls, D: 'static, Arch, R> ImageBuilder<Tls, D, Arch, R>
where
    Tls: TlsResolver,
    Arch: RelocationArch,
    R: RegionAccess,
{
    /// Create a new [`ImageBuilder`].
    ///
    /// # Arguments
    /// * `segments` - Memory segments of the ELF file
    /// * `path` - Loader source path or caller-provided source identifier
    /// * `ehdr` - ELF header
    pub(crate) fn new(
        segments: ElfSegments<R>,
        path: PathBuf,
        ehdr: ElfHeader<Arch::Layout>,
        static_tls: bool,
        page_size: usize,
        user_data: D,
    ) -> Self {
        Self {
            path,
            ehdr,
            relro: None,
            dynamic: None,
            dynamic_addr: None,
            tls_info: None,
            static_tls,
            page_size,
            segments,
            user_data,
            interp: None,
            eh_frame_hdr: None,
            _marker: PhantomData,
        }
    }

    /// Parse a program header and extract relevant information.
    pub(crate) fn parse_phdr(&mut self, phdr: &ElfPhdr<Arch::Layout>) -> Result<()> {
        match phdr.program_type() {
            ElfProgramType::DYNAMIC => {
                self.dynamic_addr = Some(self.segments.base() + phdr.p_vaddr());
                self.dynamic = Some(
                    self.segments
                        .read_view::<ElfDyn<Arch::Layout>>(phdr.p_vaddr(), phdr.p_filesz())
                        .ok_or_else(|| {
                            ParsePhdrError::malformed(
                                "PT_DYNAMIC is not directly readable from mapped segments",
                            )
                        })?,
                )
            }
            ElfProgramType::GNU_RELRO => {
                self.relro = Some(ELFRelro::new(phdr, self.segments.base(), self.page_size))
            }
            ElfProgramType::PHDR => {}
            ElfProgramType::INTERP => {
                self.interp = Some(self.read_interp(phdr)?);
            }
            ElfProgramType::GNU_EH_FRAME => {
                self.eh_frame_hdr = Some(
                    self.segments
                        .borrowed_ptr::<u8>(phdr.p_vaddr(), phdr.p_filesz())
                        .ok_or_else(|| {
                            ParsePhdrError::malformed(
                                "PT_GNU_EH_FRAME is not directly readable from mapped segments",
                            )
                        })?,
                );
            }
            ElfProgramType::TLS => {
                let tls_image = self
                    .segments
                    .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())
                    .ok_or_else(|| ParsePhdrError::malformed("PT_TLS image is malformed"))?;
                self.tls_info = Some(TlsInfo::new(phdr, tls_image.as_slice()));
            }
            _ => {}
        };
        Ok(())
    }

    fn read_interp(&self, phdr: &ElfPhdr<Arch::Layout>) -> Result<&'static str> {
        let view = self
            .segments
            .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())
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
    pub(crate) fn parse_phdrs(&mut self, phdrs: &[ElfPhdr<Arch::Layout>]) -> Result<()> {
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
    pub(crate) fn create_phdrs(
        &self,
        phdrs: &[ElfPhdr<Arch::Layout>],
    ) -> Result<ElfPhdrs<Arch::Layout>> {
        for phdr in phdrs {
            if phdr.program_type() != ElfProgramType::PHDR {
                continue;
            }
            if let Some(mapped) = self
                .segments
                .read_view::<ElfPhdr<Arch::Layout>>(phdr.p_vaddr(), phdr.p_memsz())
            {
                return Ok(ElfPhdrs::Mapped(mapped));
            }
        }

        let Some((phdr_start, phdr_end)) = self.ehdr.phdr_range()? else {
            return Ok(ElfPhdrs::Vec(Vec::from(phdrs)));
        };
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
                    .read_view::<ElfPhdr<Arch::Layout>>(phdr_vaddr, phdr_size)
                {
                    return Ok(ElfPhdrs::Mapped(mapped));
                }
            }
        }

        Ok(ElfPhdrs::Vec(Vec::from(phdrs)))
    }
}
