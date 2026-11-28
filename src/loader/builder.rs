use crate::{
    ParsePhdrError, Result,
    arch::NativeArch,
    elf::{ElfDyn, ElfHeader, ElfLayout, ElfPhdr, ElfPhdrs, ElfProgramType, NativeElfLayout},
    input::{ElfReader, ModuleSourceId, PathBuf},
    memory::{HostRegion, ImageMemory, MappedView, RegionAccess, VmAddr},
    os::ProtFlags,
    relocation::RelocationArch,
    runtime::Domain,
    segment::{ElfSegments, MemoryProtection},
    tls::{TlsInfo, TlsResolver},
};
use alloc::{boxed::Box, vec::Vec};
use core::ptr::NonNull;

pub(crate) struct DynamicSection<L: ElfLayout> {
    pub(crate) addr: VmAddr,
    pub(crate) entries: MappedView<ElfDyn<L>>,
}

/// Builder for creating relocated ELF objects
///
/// This structure is used internally during the loading process to collect
/// and organize the various components of a relocated ELF file before
/// building the final loaded image.
pub(crate) struct ImageBuilder<
    Tls,
    D: Send + Sync + 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> where
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
{
    /// Loader source path or caller-provided source identifier.
    pub(crate) path: PathBuf,

    /// Identity of the opened source.
    pub(crate) source_id: ModuleSourceId,

    /// ELF header, when the loader owns the original ELF header metadata.
    ehdr: Option<ElfHeader<Arch::Layout>>,

    /// Runtime entry point.
    pub(crate) entry: VmAddr,

    /// GNU_RELRO memory protection.
    pub(crate) relro: Option<MemoryProtection>,

    /// Dynamic section entries
    pub(crate) dynamic: Option<DynamicSection<Arch::Layout>>,

    /// TLS information
    pub(crate) tls_info: Option<TlsInfo>,

    /// Whether to use static TLS
    pub(crate) static_tls: bool,

    /// Page size used for segment layout.
    page_size: usize,

    /// User-defined data
    pub(crate) user_data: D,

    /// Fixed runtime domain selected by the loader run.
    pub(crate) domain: Domain<Arch, Tls>,

    /// Memory segments
    pub(crate) segments: ElfSegments<R>,

    /// Interpreter path (PT_INTERP)
    pub(crate) interp: Option<&'static [u8]>,

    /// Pointer to the .eh_frame_hdr section (PT_GNU_EH_FRAME)
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,
}

pub(crate) struct ScanBuilder<L: ElfLayout = NativeElfLayout> {
    pub(crate) path: PathBuf,
    pub(crate) ehdr: ElfHeader<L>,
    pub(crate) phdrs: Box<[ElfPhdr<L>]>,
    pub(crate) reader: Box<dyn ElfReader + 'static>,
}

impl<Tls, D: Send + Sync + 'static, Arch, R> ImageBuilder<Tls, D, Arch, R>
where
    Tls: TlsResolver<Arch>,
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
        source_id: ModuleSourceId,
        ehdr: Option<ElfHeader<Arch::Layout>>,
        entry: VmAddr,
        static_tls: bool,
        page_size: usize,
        user_data: D,
        domain: Domain<Arch, Tls>,
    ) -> Self {
        Self {
            path,
            source_id,
            ehdr,
            entry,
            relro: None,
            dynamic: None,
            tls_info: None,
            static_tls,
            page_size,
            segments,
            user_data,
            domain,
            interp: None,
            eh_frame_hdr: None,
        }
    }

    /// Parse a program header and extract relevant information.
    pub(crate) fn parse_phdr(&mut self, phdr: &ElfPhdr<Arch::Layout>) -> Result<()> {
        match phdr.program_type() {
            ElfProgramType::DYNAMIC => {
                self.dynamic = Some(DynamicSection {
                    addr: self.segments.base() + phdr.p_vaddr(),
                    entries: self
                        .segments
                        .read_view::<ElfDyn<Arch::Layout>>(phdr.p_vaddr(), phdr.p_filesz())
                        .ok_or_else(|| {
                            ParsePhdrError::malformed(
                                "PT_DYNAMIC is not directly readable from mapped segments",
                            )
                        })?,
                });
            }
            ElfProgramType::GNU_RELRO => {
                self.relro = Some(MemoryProtection::new(
                    self.segments.base() + phdr.p_vaddr(),
                    phdr.p_memsz(),
                    self.page_size,
                    ProtFlags::PROT_READ,
                ))
            }
            ElfProgramType::PHDR => {}
            ElfProgramType::INTERP => {
                self.interp = Some(self.read_interp(phdr)?);
            }
            ElfProgramType::GNU_EH_FRAME => {
                self.eh_frame_hdr = Some(
                    self.segments
                        .host_ptr_range(self.segments.base() + phdr.p_vaddr(), phdr.p_filesz())
                        .ok_or_else(|| {
                            ParsePhdrError::malformed(
                                "PT_GNU_EH_FRAME is not directly readable from mapped segments",
                            )
                        })?,
                );
            }
            ElfProgramType::TLS => {
                self.segments
                    .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())
                    .ok_or_else(|| ParsePhdrError::malformed("PT_TLS image is malformed"))?;
                self.tls_info = Some(TlsInfo::new(phdr));
            }
            _ => {}
        };
        Ok(())
    }

    fn read_interp(&self, phdr: &ElfPhdr<Arch::Layout>) -> Result<&'static [u8]> {
        let view = self
            .segments
            .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())
            .ok_or_else(|| {
                ParsePhdrError::malformed("PT_INTERP is not directly readable from mapped segments")
            })?;
        crate::elf::parse_interp(view.as_slice())
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

        let Some(ehdr) = &self.ehdr else {
            return Ok(ElfPhdrs::Vec(Vec::from(phdrs)));
        };
        let Some((phdr_start, phdr_end)) = ehdr.phdr_range()? else {
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
