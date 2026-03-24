use crate::{
    Result,
    elf::ElfPhdr,
    os::{MapFlags, Mmap, ProtFlags},
    segment::{
        Address, ElfSegment, ElfSegments, FileMapInfo, PAGE_SIZE, SegmentBuilder, rounddown,
        roundup,
    },
};
use alloc::vec::Vec;
use elf::abi::{PF_R, PF_W, PF_X, PT_LOAD};

/// Convert ELF program header flags to memory protection flags
#[inline]
fn segment_prot(p_flag: u32) -> ProtFlags {
    // Map ELF flags (PF_X, PF_W, PF_R) to memory protection flags
    // PF_X (execute) -> PROT_EXEC (bit 2)
    // PF_W (write)   -> PROT_WRITE (bit 1)
    // PF_R (read)    -> PROT_READ (bit 0)
    ProtFlags::from_bits_retain(((p_flag & PF_X) << 2 | p_flag & PF_W | (p_flag & PF_R) >> 2) as _)
}

/// Manages segments parsed from ELF program headers
pub(crate) struct ProgramSegments<'phdr> {
    phdrs: &'phdr [ElfPhdr],
    segments: Vec<ElfSegment>,
    is_dylib: bool,
    use_file: bool,
}

impl<'phdr> ProgramSegments<'phdr> {
    /// Create a new PhdrSegments instance
    pub(crate) fn new(phdrs: &'phdr [ElfPhdr], is_dylib: bool, use_file: bool) -> Self {
        Self {
            phdrs,
            segments: Vec::new(),
            is_dylib,
            use_file,
        }
    }
}

/// Parse segments to determine memory layout requirements
#[inline]
fn parse_segments(phdrs: &[ElfPhdr], is_dylib: bool) -> (Option<usize>, usize, usize) {
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0;

    // Find the minimum and maximum virtual addresses of LOAD segments
    for phdr in phdrs {
        if phdr.p_type == PT_LOAD {
            let vaddr_start = phdr.p_vaddr as usize;
            let vaddr_end = (phdr.p_vaddr + phdr.p_memsz) as usize;
            if vaddr_start < min_vaddr {
                min_vaddr = vaddr_start;
            }
            if vaddr_end > max_vaddr {
                max_vaddr = vaddr_end;
            }
        }
    }

    // Align addresses to page boundaries
    max_vaddr = roundup(max_vaddr, PAGE_SIZE);
    min_vaddr = rounddown(min_vaddr, PAGE_SIZE);
    let total_size = max_vaddr - min_vaddr;

    // For shared libraries, let the OS choose the base address (None)
    // For executables, suggest the preferred base address (Some)
    (
        if is_dylib { None } else { Some(min_vaddr) },
        total_size,
        min_vaddr,
    )
}

impl SegmentBuilder for ProgramSegments<'_> {
    /// Reserve memory space for all segments
    fn create_space<M: Mmap>(&mut self) -> Result<ElfSegments> {
        let (addr, len, min_vaddr) = parse_segments(self.phdrs, self.is_dylib);
        let ptr = unsafe { M::mmap_reserve(addr, len, self.use_file) }?;
        let mut segments = ElfSegments::new(ptr, len, M::munmap);
        segments.offset = min_vaddr;
        Ok(segments)
    }

    /// Create individual segments from program headers
    fn create_segments(&mut self) -> Result<()> {
        for phdr in self.phdrs.iter().filter(|phdr| phdr.p_type == PT_LOAD) {
            self.segments.push(phdr.create_segment());
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

impl ElfPhdr {
    /// Create an ElfSegment from an ELF program header
    #[inline]
    fn create_segment(&self) -> ElfSegment {
        // Align segment boundaries to page size
        let min_vaddr = rounddown(self.p_vaddr as usize, PAGE_SIZE);
        let max_vaddr = roundup((self.p_vaddr + self.p_memsz) as usize, PAGE_SIZE);
        let memsz = max_vaddr - min_vaddr;
        let prot = segment_prot(self.p_flags);

        // Align file offset to page boundary
        let offset = rounddown(self.p_offset as usize, PAGE_SIZE);
        // Account for alignment adjustment in file size
        let align_len = self.p_offset as usize - offset;
        let filesz = self.p_filesz as usize + align_len;

        ElfSegment {
            addr: Address::Relative(min_vaddr),
            prot,
            flags: MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            len: memsz,
            content_size: filesz,
            zero_size: (self.p_memsz - self.p_filesz) as usize,
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
