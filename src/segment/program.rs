use crate::{
    Error, MmapError, ParsePhdrError, Result,
    elf::{ElfLayout, ElfPhdr, ElfProgramFlags, ElfProgramType},
    input::{ElfReader, FileBacking, check_read_range},
    memory::{VmAddr, VmOffset, rounddown, roundup},
    os::{Mmap, ProtFlags, SpaceInit, SpaceLayout},
    segment::{ElfSegment, ElfSegments, SegmentContent, populate_segments, protect_segments},
};

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

/// Validates program headers, creates the address space, and populates its segments.
pub(crate) fn load_segments<M>(
    phdrs: &[ElfPhdr<impl ElfLayout>],
    is_dylib: bool,
    mapper: &M,
    object: &impl ElfReader,
    page_size: usize,
) -> Result<ElfSegments<M::Region>>
where
    M: Mmap + ?Sized,
{
    for phdr in phdrs {
        if phdr.program_type() == ElfProgramType::LOAD && phdr.p_filesz() != 0 {
            check_read_range(phdr.p_offset(), phdr.p_filesz(), object.len())?;
        }
    }
    let file_backing = match object.file_backing() {
        Some(range) => mapper.file_backing(range)?,
        None => None,
    };
    let layout = parse_segments(phdrs, is_dylib, page_size)?;
    let segments = phdrs
        .iter()
        .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
        .map(|phdr| phdr.create_segment(page_size));
    let mut remaining = segments.clone();
    let use_file = file_backing.is_some();
    let loaded = if is_dylib
        && let Some(backing) = file_backing
        && let Some(loaded) = map_first_segment(phdrs, mapper, &layout, backing, page_size)?
    {
        // The initial file mapping already populated the first LOAD segment.
        remaining.next();
        loaded
    } else {
        let (prot, init) = if use_file {
            (ProtFlags::PROT_NONE, SpaceInit::Reserve)
        } else {
            (ProtFlags::PROT_WRITE, SpaceInit::Zeroed)
        };
        let region = unsafe { mapper.create_space(layout, prot, init) }?;
        let min_vaddr = VmOffset::new(layout.offset);
        let base = region.addr() - min_vaddr;
        ElfSegments::new(region, base, min_vaddr)
    };
    populate_segments(mapper, object, &loaded, remaining, file_backing)?;
    if !use_file {
        protect_segments(&loaded, segments)?;
    }
    Ok(loaded)
}

/// Creates the image's address space with a file mapping and completes its first
/// LOAD segment. The caller populates the remaining segments through the common path.
fn map_first_segment<M: Mmap + ?Sized>(
    phdrs: &[ElfPhdr<impl ElfLayout>],
    mapper: &M,
    layout: &SpaceLayout,
    backing: FileBacking,
    page_size: usize,
) -> Result<Option<ElfSegments<M::Region>>> {
    let loads = phdrs
        .iter()
        .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD);
    let Some(first) = loads.clone().next() else {
        return Ok(None);
    };
    if first.p_filesz() == 0 {
        return Ok(None);
    }
    // The single middle-range protection below requires non-overlapping pages.
    // Other layouts still use the common reservation and segment-mapping path.
    let mut end = layout.offset;
    let mut last_start = end;
    let mut has_holes = false;
    for phdr in loads.clone() {
        let start = rounddown(phdr.p_vaddr().get(), page_size);
        if start < end {
            return Ok(None);
        }
        has_holes |= start > end;
        last_start = start;
        end = roundup(phdr.p_vaddr().get() + phdr.p_memsz(), page_size);
    }

    let initial_file_offset = rounddown(first.p_offset(), page_size);
    let offset = backing
        .offset
        .checked_add(initial_file_offset)
        .ok_or(crate::IoError::ReadBufferTooLarge)?;
    let segment = first.create_segment(page_size);
    // SAFETY: LOAD ranges were validated against the reader before this call.
    // No bytes are accessed until their file offset and permissions are fixed;
    // any full BSS pages are replaced with anonymous pages before publication.
    let region = match unsafe {
        mapper.create_space(
            *layout,
            segment.prot,
            SpaceInit::File {
                fd: backing.fd,
                offset,
            },
        )
    } {
        Ok(region) => region,
        Err(Error::Mmap(MmapError::FileMappingUnsupported)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let min_vaddr = VmOffset::new(layout.offset);
    let base = region.addr() - min_vaddr;
    let loaded = ElfSegments::new(region, base, min_vaddr);
    let SegmentContent::Contiguous {
        file_size,
        zero_size,
        ..
    } = &segment.content
    else {
        unreachable!("program segments have contiguous file contents");
    };
    if has_holes {
        // Protect the whole middle range once. BSS population and later segment
        // mappings restore their own pages, leaving only the gaps inaccessible.
        let file_end = segment.offset.get() + roundup(*file_size, page_size);
        loaded.mprotect(
            base + VmOffset::new(file_end),
            last_start - file_end,
            ProtFlags::PROT_NONE,
        )?;
    }
    segment.fill_zero(mapper, &loaded, *file_size, *zero_size)?;
    Ok(Some(loaded))
}

/// Parses LOAD memory layout requirements, retaining the lowest page-aligned
/// virtual address in `offset`.
#[inline]
pub(crate) fn parse_segments(
    phdrs: &[ElfPhdr<impl ElfLayout>],
    is_dylib: bool,
    page_size: usize,
) -> Result<SpaceLayout> {
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0;
    let mut has_load_segment = false;
    let mut alignment = page_size;

    // Find the minimum and maximum virtual addresses of LOAD segments
    for phdr in phdrs {
        if phdr.program_type() == ElfProgramType::LOAD {
            let vaddr_start = phdr.p_vaddr();
            if vaddr_start.get() % page_size != phdr.p_offset() % page_size {
                return Err(ParsePhdrError::PageAlignmentMismatch { page_size }.into());
            }

            has_load_segment = true;
            alignment = alignment.max(phdr.p_align());
            if phdr.p_filesz() > phdr.p_memsz() {
                return Err(ParsePhdrError::malformed("PT_LOAD p_filesz exceeds p_memsz").into());
            }

            let vaddr_end = vaddr_start
                .checked_add(phdr.p_memsz())
                .map(VmOffset::get)
                .ok_or(ParsePhdrError::malformed(
                    "PT_LOAD virtual address range overflows",
                ))?;
            let vaddr_start = vaddr_start.get();
            if vaddr_start < min_vaddr {
                min_vaddr = vaddr_start;
            }
            if vaddr_end > max_vaddr {
                max_vaddr = vaddr_end;
            }
        }
    }

    if !has_load_segment {
        return Err(ParsePhdrError::malformed("program headers do not contain PT_LOAD").into());
    }
    if !alignment.is_power_of_two() {
        return Err(ParsePhdrError::malformed("PT_LOAD alignment is not a power of two").into());
    }

    // Align addresses to page boundaries
    max_vaddr = roundup(max_vaddr, page_size);
    min_vaddr = rounddown(min_vaddr, page_size);
    let total_size = max_vaddr
        .checked_sub(min_vaddr)
        .filter(|size| *size != 0)
        .ok_or(ParsePhdrError::malformed(
            "PT_LOAD virtual address range is empty or inverted",
        ))?;

    // For shared libraries, let the OS choose the base address (None)
    // For executables, suggest the preferred base address (Some)
    Ok(SpaceLayout {
        addr: if is_dylib {
            None
        } else {
            Some(VmAddr::new(min_vaddr))
        },
        len: total_size,
        align: alignment,
        offset: min_vaddr,
    })
}

impl<L: ElfLayout> ElfPhdr<L> {
    /// Create an ElfSegment from an ELF program header
    #[inline]
    fn create_segment(&self, page_size: usize) -> ElfSegment {
        // Align segment boundaries to page size
        let p_vaddr = self.p_vaddr().get();
        let min_vaddr = rounddown(p_vaddr, page_size);
        let max_vaddr = roundup(p_vaddr + self.p_memsz(), page_size);
        let memsz = max_vaddr - min_vaddr;
        let prot = segment_prot(self.flags());

        // Align file offset to page boundary
        let offset = rounddown(self.p_offset(), page_size);
        // Account for alignment adjustment in file size
        let align_len = self.p_offset() - offset;
        let filesz = self.p_filesz() + align_len;

        ElfSegment {
            offset: VmOffset::new(min_vaddr),
            prot,
            len: memsz,
            page_size,
            content: SegmentContent::Contiguous {
                file_offset: offset,
                file_size: filesz,
                zero_size: self.p_memsz() - self.p_filesz(),
            },
        }
    }
}
