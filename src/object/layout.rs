use crate::{
    Result,
    arch::object::{ObjectRelocator, PLT_ENTRY, PLT_ENTRY_SIZE},
    elf::{ElfRelType, ElfShdr, Shdr},
    input::ElfReader,
    os::{MapFlags, Mmap, ProtFlags},
    relocation::RelocAddr,
    segment::{
        Address, ElfSegment, ElfSegments, FileMapInfo, PAGE_SIZE, SegmentBuilder, rounddown,
        roundup,
    },
};
use alloc::vec::Vec;
use elf::abi::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_REL, SHT_RELA};
use hashbrown::{HashMap, HashSet, hash_map::Entry};

use super::ObjectReloc;

/// Convert section flags to memory protection flags
pub(crate) fn section_prot(sh_flags: impl Into<u64>) -> ProtFlags {
    let sh_flags = sh_flags.into();
    let mut prot = ProtFlags::PROT_READ;
    if sh_flags & SHF_WRITE as u64 != 0 {
        prot |= ProtFlags::PROT_WRITE;
    }
    if sh_flags & SHF_EXECINSTR as u64 != 0 {
        prot |= ProtFlags::PROT_EXEC;
    }
    prot
}

/// Manages segments created from ELF section headers
pub(crate) struct SectionSegments {
    segments: Vec<ElfSegment>,
    total_size: usize,
    pltgot: Option<PltGotSection>,
}

fn prot_to_idx(prot: ProtFlags) -> usize {
    usize::from(prot.contains(ProtFlags::PROT_WRITE))
        | (usize::from(prot.contains(ProtFlags::PROT_EXEC)) << 1)
}

fn flags_to_idx(flags: impl Into<u64>) -> usize {
    prot_to_idx(section_prot(flags))
}

impl SegmentBuilder for SectionSegments {
    fn create_space<M: Mmap>(&mut self) -> Result<ElfSegments> {
        let len = self.total_size;
        let memory = unsafe { M::mmap_reserve(None, len, false) }?;
        Ok(ElfSegments::new(memory, len, M::munmap))
    }

    fn create_segments(&mut self) -> Result<()> {
        Ok(())
    }

    fn segments_mut(&mut self) -> &mut [ElfSegment] {
        &mut self.segments
    }

    fn segments(&self) -> &[ElfSegment] {
        &self.segments
    }
}

impl SectionSegments {
    pub(crate) fn new(shdrs: &mut [ElfShdr], object: &mut impl ElfReader) -> Result<Self> {
        let mut units: [SectionUnit; 4] = core::array::from_fn(|_| SectionUnit::new());

        let (got_cnt, plt_cnt) = PltGotSection::count_needed_entries(shdrs, object)?;

        let mut got_shdr = PltGotSection::create_got_shdr(got_cnt);
        let mut plt_shdr = PltGotSection::create_plt_shdr(plt_cnt);

        for shdr in shdrs.iter_mut().chain([&mut got_shdr, &mut plt_shdr]) {
            units[flags_to_idx(shdr.sh_flags)].add_section(shdr);
        }

        let mut segments = Vec::new();
        let mut offset = 0;
        for unit in &mut units {
            if let Some(segment) = unit.create_segment(&mut offset) {
                offset = roundup(offset, PAGE_SIZE);
                segments.push(segment);
            }
        }

        Ok(Self {
            segments,
            total_size: offset,
            pltgot: Some(PltGotSection::new(&got_shdr, &plt_shdr)),
        })
    }

    pub(crate) fn take_pltgot(&mut self) -> PltGotSection {
        self.pltgot.take().expect("PLTGOT already taken")
    }
}

/// Manages PLT (Procedure Linkage Table) and GOT (Global Offset Table) sections
pub(crate) struct PltGotSection {
    got_base: RelocAddr,
    plt_base: RelocAddr,
    got_idx: usize,
    plt_idx: usize,
    got_map: HashMap<usize, usize>,
    plt_map: HashMap<usize, usize>,
}

pub(crate) struct UsizeEntry<'entry>(&'entry mut usize);

impl UsizeEntry<'_> {
    pub(crate) fn update(&mut self, value: RelocAddr) {
        *self.0 = value.into_inner();
    }

    pub(crate) fn get_addr(&self) -> RelocAddr {
        RelocAddr::from_ptr(self.0 as *const _)
    }
}

pub(crate) enum GotEntry<'got> {
    Occupied(RelocAddr),
    Vacant(UsizeEntry<'got>),
}

pub(crate) enum PltEntry<'plt> {
    Occupied(RelocAddr),
    Vacant {
        plt: &'plt mut [u8],
        got: UsizeEntry<'plt>,
    },
}

impl PltGotSection {
    fn count_needed_entries(
        shdrs: &[ElfShdr],
        object: &mut impl ElfReader,
    ) -> Result<(usize, usize)> {
        let mut got_set = HashSet::new();
        let mut plt_set = HashSet::new();

        for shdr in shdrs
            .iter()
            .filter(|s| matches!(s.sh_type, SHT_REL | SHT_RELA))
        {
            let size = shdr.sh_size as usize;
            let entsize = shdr.sh_entsize as usize;
            if size == 0 || entsize == 0 {
                continue;
            }

            let mut buf = alloc::vec![0u8; size];
            object.read(&mut buf, shdr.sh_offset as usize)?;

            for chunk in buf.chunks_exact(entsize) {
                let rel_entry =
                    unsafe { core::ptr::read_unaligned(chunk.as_ptr() as *const ElfRelType) };
                let r_type = rel_entry.r_type() as u32;
                let r_sym = rel_entry.r_symbol();

                if ObjectRelocator::needs_got(r_type) {
                    got_set.insert(r_sym);
                }
                if ObjectRelocator::needs_plt(r_type) {
                    plt_set.insert(r_sym);
                }
            }
        }

        Ok((got_set.len() + plt_set.len(), plt_set.len()))
    }

    fn create_got_shdr(elem_cnt: usize) -> ElfShdr {
        ElfShdr::new(
            0,
            SHT_NOBITS,
            (SHF_ALLOC | SHF_WRITE) as _,
            0,
            0,
            elem_cnt * size_of::<usize>(),
            0,
            0,
            16,
            size_of::<usize>(),
        )
    }

    fn create_plt_shdr(elem_cnt: usize) -> ElfShdr {
        ElfShdr::new(
            0,
            SHT_NOBITS,
            (SHF_ALLOC | SHF_EXECINSTR) as _,
            0,
            0,
            elem_cnt * PLT_ENTRY_SIZE,
            0,
            0,
            size_of::<usize>(),
            PLT_ENTRY_SIZE,
        )
    }

    fn new(got: &Shdr, plt: &Shdr) -> Self {
        Self {
            got_idx: 0,
            plt_idx: 0,
            got_map: HashMap::new(),
            plt_map: HashMap::new(),
            got_base: RelocAddr::new(got.sh_addr as usize),
            plt_base: RelocAddr::new(plt.sh_addr as usize),
        }
    }

    pub(crate) fn rebase(&mut self, base: RelocAddr) {
        self.got_base = self.got_base.offset(base.into_inner());
        self.plt_base = self.plt_base.offset(base.into_inner());
    }

    pub(crate) fn add_got_entry(&mut self, r_sym: usize) -> GotEntry<'_> {
        let base = self.got_base;
        let ent_size = size_of::<usize>();
        match self.got_map.entry(r_sym) {
            Entry::Occupied(mut entry) => {
                GotEntry::Occupied(base.offset(*entry.get_mut() * ent_size))
            }
            Entry::Vacant(entry) => {
                let idx = *entry.insert(self.got_idx);
                self.got_idx += 1;
                GotEntry::Vacant(unsafe {
                    UsizeEntry(&mut *base.offset(idx * ent_size).as_mut_ptr())
                })
            }
        }
    }

    pub(crate) fn add_plt_entry(&mut self, r_sym: usize) -> PltEntry<'_> {
        let plt_base = self.plt_base;
        let got_base = self.got_base;
        let plt_ent_size = PLT_ENTRY_SIZE;
        let got_ent_size = size_of::<usize>();
        match self.plt_map.entry(r_sym) {
            Entry::Occupied(mut entry) => {
                PltEntry::Occupied(plt_base.offset(*entry.get_mut() * plt_ent_size))
            }
            Entry::Vacant(entry) => {
                let plt_idx = *entry.insert(self.plt_idx);
                self.plt_idx += 1;

                let got_idx = self.got_idx;
                self.got_idx += 1;

                let plt = unsafe {
                    core::slice::from_raw_parts_mut(
                        plt_base.offset(plt_idx * plt_ent_size).as_mut_ptr(),
                        plt_ent_size,
                    )
                };

                plt.copy_from_slice(&PLT_ENTRY);

                PltEntry::Vacant {
                    plt,
                    got: unsafe {
                        UsizeEntry(&mut *got_base.offset(got_idx * got_ent_size).as_mut_ptr())
                    },
                }
            }
        }
    }
}

struct SectionUnit<'shdr> {
    content_sections: Vec<&'shdr mut ElfShdr>,
    zero_sections: Vec<&'shdr mut ElfShdr>,
}

impl<'shdr> SectionUnit<'shdr> {
    fn new() -> Self {
        Self {
            content_sections: Vec::new(),
            zero_sections: Vec::new(),
        }
    }

    fn add_section(&mut self, shdr: &'shdr mut ElfShdr) {
        if shdr.sh_type == SHT_NOBITS {
            self.zero_sections.push(shdr);
        } else {
            self.content_sections.push(shdr);
        }
    }

    fn create_segment(&mut self, base_offset: &mut usize) -> Option<ElfSegment> {
        let first_shdr = self
            .content_sections
            .first()
            .or(self.zero_sections.first())?;

        let prot = section_prot(first_shdr.sh_flags);
        let segment_start = *base_offset;
        let addr = Address::Relative(segment_start);

        let mut current_offset = segment_start;
        let mut map_info = Vec::new();
        for shdr in &mut self.content_sections {
            if shdr.sh_size == 0 {
                continue;
            }
            current_offset = roundup(current_offset, shdr.sh_addralign as usize);
            shdr.sh_addr = current_offset as _;
            map_info.push(FileMapInfo {
                filesz: shdr.sh_size as usize,
                offset: shdr.sh_offset as usize,
                start: current_offset - segment_start,
            });
            current_offset += shdr.sh_size as usize;
        }

        if map_info.len() == 1 {
            let info = &mut map_info[0];
            let file_offset = rounddown(info.offset, PAGE_SIZE);
            let align_len = info.offset - file_offset;

            let shdr = self
                .content_sections
                .iter_mut()
                .find(|shdr| shdr.sh_offset as usize == info.offset)
                .unwrap();

            shdr.sh_addr = shdr.sh_addr.wrapping_add(align_len as _);
            info.filesz += align_len;
            info.offset = file_offset;
            current_offset += align_len;
        }

        let content_size = current_offset - segment_start;

        for shdr in &mut self.zero_sections {
            current_offset = roundup(current_offset, shdr.sh_addralign as usize);
            shdr.sh_addr = current_offset as _;
            current_offset += shdr.sh_size as usize;
        }

        let unaligned_total_size = current_offset - segment_start;
        let total_size = roundup(unaligned_total_size, PAGE_SIZE);

        if total_size == 0 {
            return None;
        }

        *base_offset += total_size;
        Some(ElfSegment {
            addr,
            prot,
            len: total_size,
            content_size,
            zero_size: unaligned_total_size - content_size,
            need_copy: false,
            flags: MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            map_info,
            from_relocatable: true,
        })
    }
}
