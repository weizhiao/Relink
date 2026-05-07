use crate::{
    ParsePhdrError, Result,
    elf::{ElfLayout, ElfPhdr, ElfProgramFlags, ElfProgramType, NativeElfLayout},
    os::{MapFlags, Mmap, ProtFlags},
    segment::{Address, ElfSegment, ElfSegments, FileMapInfo, SegmentBuilder, rounddown, roundup},
};
use alloc::vec::Vec;

/// Convert ELF program header flags to memory protection flags
#[inline]
fn segment_prot(flags: ElfProgramFlags) -> ProtFlags {
    let mut prot = ProtFlags::PROT_NONE;
    if flags.contains(ElfProgramFlags::READ) {
        prot |= ProtFlags::PROT_READ;
    }
    if flags.contains(ElfProgramFlags::WRITE) {
        prot |= ProtFlags::PROT_WRITE;
    }
    if flags.contains(ElfProgramFlags::EXEC) {
        prot |= ProtFlags::PROT_EXEC;
    }
    prot
}

/// Manages segments parsed from ELF program headers
pub(crate) struct ProgramSegments<'phdr, L: ElfLayout = NativeElfLayout> {
    phdrs: &'phdr [ElfPhdr<L>],
    segments: Vec<ElfSegment>,
    is_dylib: bool,
    use_file: bool,
    page_size: usize,
}

impl<'phdr, L: ElfLayout> ProgramSegments<'phdr, L> {
    /// Create a new [`ProgramSegments`] instance.
    pub(crate) fn new(
        phdrs: &'phdr [ElfPhdr<L>],
        is_dylib: bool,
        use_file: bool,
        page_size: usize,
    ) -> Self {
        Self {
            phdrs,
            segments: Vec::new(),
            is_dylib,
            use_file,
            page_size,
        }
    }
}

/// Memory layout requirements derived from LOAD program headers.
pub(crate) struct ProgramSegmentLayout {
    /// Preferred address passed to `mmap`; `None` lets the OS choose.
    pub(crate) preferred_addr: Option<usize>,
    /// Total page-aligned memory range covered by LOAD segments.
    pub(crate) mapped_len: usize,
    /// Lowest page-aligned virtual address among LOAD segments.
    pub(crate) min_vaddr: usize,
}

/// Parse segments to determine memory layout requirements
#[inline]
pub(crate) fn parse_segments(
    phdrs: &[ElfPhdr<impl ElfLayout>],
    is_dylib: bool,
    page_size: usize,
) -> Result<ProgramSegmentLayout> {
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0;
    let mut has_load_segment = false;

    // Find the minimum and maximum virtual addresses of LOAD segments
    for phdr in phdrs {
        if phdr.program_type() == ElfProgramType::LOAD {
            if phdr.p_vaddr() % page_size != phdr.p_offset() % page_size {
                return Err(ParsePhdrError::PageAlignmentMismatch { page_size }.into());
            }

            has_load_segment = true;
            let vaddr_start = phdr.p_vaddr();
            let vaddr_end = phdr
                .p_vaddr()
                .checked_add(phdr.p_memsz())
                .ok_or(ParsePhdrError::MalformedProgramHeaders)?;
            if vaddr_start < min_vaddr {
                min_vaddr = vaddr_start;
            }
            if vaddr_end > max_vaddr {
                max_vaddr = vaddr_end;
            }
        }
    }

    if !has_load_segment {
        return Err(ParsePhdrError::MalformedProgramHeaders.into());
    }

    // Align addresses to page boundaries
    max_vaddr = roundup(max_vaddr, page_size);
    min_vaddr = rounddown(min_vaddr, page_size);
    let total_size = max_vaddr
        .checked_sub(min_vaddr)
        .ok_or(ParsePhdrError::MalformedProgramHeaders)?;

    // For shared libraries, let the OS choose the base address (None)
    // For executables, suggest the preferred base address (Some)
    Ok(ProgramSegmentLayout {
        preferred_addr: if is_dylib { None } else { Some(min_vaddr) },
        mapped_len: total_size,
        min_vaddr,
    })
}

impl<L: ElfLayout> SegmentBuilder for ProgramSegments<'_, L> {
    /// Reserve memory space for all segments
    fn create_space<M: Mmap>(&mut self) -> Result<ElfSegments> {
        let layout = parse_segments(self.phdrs, self.is_dylib, self.page_size)?;
        let ptr =
            unsafe { M::mmap_reserve(layout.preferred_addr, layout.mapped_len, self.use_file) }?;
        Ok(ElfSegments::with_base(
            ptr,
            layout.mapped_len,
            M::munmap,
            (ptr as usize).wrapping_sub(layout.min_vaddr),
            layout.min_vaddr,
        ))
    }

    /// Create individual segments from program headers
    fn create_segments(&mut self) -> Result<()> {
        for phdr in self
            .phdrs
            .iter()
            .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
        {
            self.segments.push(phdr.create_segment(self.page_size));
        }
        Ok(())
    }

    /// Get mutable reference to segments
    fn segments_mut(&mut self) -> &mut [ElfSegment] {
        &mut self.segments
    }

    /// Get reference to segments
    fn segments(&self) -> &[ElfSegment] {
        &self.segments
    }
}

impl<L: ElfLayout> ElfPhdr<L> {
    /// Create an ElfSegment from an ELF program header
    #[inline]
    fn create_segment(&self, page_size: usize) -> ElfSegment {
        // Align segment boundaries to page size
        let min_vaddr = rounddown(self.p_vaddr(), page_size);
        let max_vaddr = roundup(self.p_vaddr() + self.p_memsz(), page_size);
        let memsz = max_vaddr - min_vaddr;
        let prot = segment_prot(self.flags());

        // Align file offset to page boundary
        let offset = rounddown(self.p_offset(), page_size);
        // Account for alignment adjustment in file size
        let align_len = self.p_offset() - offset;
        let filesz = self.p_filesz() + align_len;

        ElfSegment {
            addr: Address::Relative(min_vaddr),
            prot,
            flags: MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            len: memsz,
            page_size,
            content_size: filesz,
            zero_size: self.p_memsz() - self.p_filesz(),
            map_info: alloc::vec![FileMapInfo {
                start: 0,
                filesz,
                offset,
            }],
            need_copy: false,
            from_relocatable: false,
        }
    }
}
