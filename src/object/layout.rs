use crate::{
    AlignedBytes, Result,
    arch::object::{PLT_ENTRY, PLT_ENTRY_SIZE},
    elf::{
        ElfLayout, ElfRelEntry, ElfRelType, ElfSectionFlags, ElfSectionId, ElfSectionType,
        ElfSections, ElfShdr,
    },
    input::{ElfReader, ElfReaderExt},
    os::{MapFlags, Mmap, ProtFlags, VmAddr, VmOffset, rounddown, roundup},
    relocation::{ObjectRelocationArch, RelocationArch},
    segment::{ElfSegment, ElfSegments, FileMapInfo, SegmentBuilder},
};
use alloc::vec::Vec;
use hashbrown::{HashMap, HashSet, hash_map::Entry};

/// Convert section flags to memory protection flags
pub(crate) fn section_prot(sh_flags: ElfSectionFlags) -> ProtFlags {
    let mut prot = ProtFlags::PROT_READ;
    if sh_flags.contains(ElfSectionFlags::WRITE) {
        prot |= ProtFlags::PROT_WRITE;
    }
    if sh_flags.contains(ElfSectionFlags::EXECINSTR) {
        prot |= ProtFlags::PROT_EXEC;
    }
    prot
}

/// Manages segments created from ELF section headers
pub(crate) struct SectionSegments<Arch: ObjectRelocationArch = crate::arch::NativeArch> {
    segments: Vec<ElfSegment>,
    total_size: usize,
    pltgot: Option<PltGotSection>,
    _arch: core::marker::PhantomData<Arch>,
}

fn prot_to_idx(prot: ProtFlags) -> usize {
    usize::from(prot.contains(ProtFlags::PROT_WRITE))
        | (usize::from(prot.contains(ProtFlags::PROT_EXEC)) << 1)
}

fn flags_to_idx(flags: ElfSectionFlags) -> usize {
    prot_to_idx(section_prot(flags))
}

enum PltGotShdr<L: ElfLayout> {
    Existing(ElfSectionId),
    Synthetic(ElfShdr<L>),
}

impl<L: ElfLayout> PltGotShdr<L> {
    #[inline]
    fn new(existing: Option<ElfSectionId>, synthetic: impl FnOnce() -> ElfShdr<L>) -> Self {
        match existing {
            Some(id) => Self::Existing(id),
            None => Self::Synthetic(synthetic()),
        }
    }

    #[inline]
    fn addr(&self, sections: &ElfSections<'_, L>) -> VmAddr {
        let addr = match self {
            Self::Existing(id) => sections.section(*id).sh_addr(),
            Self::Synthetic(shdr) => shdr.sh_addr(),
        };
        VmAddr::new(addr)
    }
}

struct PltGotShdrs<L: ElfLayout> {
    got: PltGotShdr<L>,
    got_plt: PltGotShdr<L>,
    plt: PltGotShdr<L>,
}

fn prepare_pltgot_shdrs<L: ElfLayout>(
    sections: &mut ElfSections<'_, L>,
    got_cnt: usize,
    plt_cnt: usize,
) -> PltGotShdrs<L> {
    let mut got = None;
    let mut got_plt = None;
    let mut plt = None;
    for index in 0..sections.headers().len() {
        let id = ElfSectionId::new(index);
        match sections.section_name(id).to_bytes() {
            b".got" => got = Some(id),
            b".got.plt" => got_plt = Some(id),
            b".plt" => plt = Some(id),
            _ => {}
        }
    }

    if let Some(id) = got {
        configure_pltgot_shdr(
            &mut sections.headers_mut()[id.index()],
            ElfSectionFlags::ALLOC | ElfSectionFlags::WRITE,
            got_cnt,
            size_of::<usize>(),
        );
    }
    if let Some(id) = got_plt {
        configure_pltgot_shdr(
            &mut sections.headers_mut()[id.index()],
            ElfSectionFlags::ALLOC | ElfSectionFlags::WRITE,
            plt_cnt,
            size_of::<usize>(),
        );
    }
    if let Some(id) = plt {
        configure_pltgot_shdr(
            &mut sections.headers_mut()[id.index()],
            ElfSectionFlags::ALLOC | ElfSectionFlags::EXECINSTR,
            plt_cnt,
            PLT_ENTRY_SIZE,
        );
        sections.headers_mut()[id.index()].set_sh_addralign(size_of::<usize>());
    }

    PltGotShdrs {
        got: PltGotShdr::new(got, || PltGotSection::create_got_shdr(got_cnt)),
        got_plt: PltGotShdr::new(got_plt, || PltGotSection::create_got_plt_shdr(plt_cnt)),
        plt: PltGotShdr::new(plt, || PltGotSection::create_plt_shdr(plt_cnt)),
    }
}

fn configure_pltgot_shdr<L: ElfLayout>(
    shdr: &mut ElfShdr<L>,
    flags: ElfSectionFlags,
    elem_cnt: usize,
    ent_size: usize,
) {
    shdr.set_section_type(ElfSectionType::NOBITS);
    shdr.set_flags(flags);
    shdr.set_sh_size(elem_cnt * ent_size);
    shdr.set_sh_addralign(16);
    shdr.set_sh_entsize(ent_size);
}

fn create_pltgot_shdr<L: ElfLayout>(
    flags: ElfSectionFlags,
    elem_cnt: usize,
    ent_size: usize,
) -> ElfShdr<L> {
    ElfShdr::new(
        0,
        ElfSectionType::NOBITS,
        flags,
        0,
        0,
        elem_cnt * ent_size,
        0,
        0,
        16,
        ent_size,
    )
}

impl<Arch: ObjectRelocationArch> SegmentBuilder for SectionSegments<Arch> {
    fn create_space<M>(&mut self, mapper: &M) -> Result<ElfSegments<M::Region>>
    where
        M: Mmap + ?Sized,
    {
        let len = self.total_size;
        let region = unsafe {
            mapper.create_space(
                None,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                false,
            )
        }?;
        let base = region.addr();
        Ok(ElfSegments::new(region, base, VmOffset::new(0)))
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

impl<Arch: ObjectRelocationArch> SectionSegments<Arch> {
    pub(crate) fn new(
        sections: &mut ElfSections<'_, Arch::Layout>,
        object: &impl ElfReader,
        page_size: usize,
    ) -> Result<Self> {
        let mut units: [SectionUnit<Arch::Layout>; 4] =
            core::array::from_fn(|_| SectionUnit::new());

        let (got_cnt, plt_cnt) =
            PltGotSection::count_needed_entries::<Arch>(sections.headers(), object)?;

        let mut pltgot_shdrs = prepare_pltgot_shdrs(sections, got_cnt, plt_cnt);

        for shdr in sections.headers_mut().iter_mut() {
            units[flags_to_idx(shdr.flags())].add_section(shdr);
        }
        if let PltGotShdr::Synthetic(shdr) = &mut pltgot_shdrs.got {
            units[flags_to_idx(shdr.flags())].add_section(shdr);
        }
        if let PltGotShdr::Synthetic(shdr) = &mut pltgot_shdrs.got_plt {
            units[flags_to_idx(shdr.flags())].add_section(shdr);
        }
        if let PltGotShdr::Synthetic(shdr) = &mut pltgot_shdrs.plt {
            units[flags_to_idx(shdr.flags())].add_section(shdr);
        }

        let mut segments = Vec::new();
        let mut offset = 0;
        for unit in &mut units {
            if let Some(segment) = unit.create_segment(&mut offset, page_size) {
                offset = roundup(offset, page_size);
                segments.push(segment);
            }
        }
        drop(units);

        let got_base = pltgot_shdrs.got.addr(sections);
        let got_plt_base = pltgot_shdrs.got_plt.addr(sections);
        let plt_base = pltgot_shdrs.plt.addr(sections);

        Ok(Self {
            segments,
            total_size: offset,
            pltgot: Some(PltGotSection::new(got_base, got_plt_base, plt_base)),
            _arch: core::marker::PhantomData,
        })
    }

    pub(crate) fn take_pltgot(&mut self) -> PltGotSection {
        self.pltgot.take().expect("PLTGOT already taken")
    }
}

/// Manages PLT (Procedure Linkage Table) and GOT (Global Offset Table) sections
pub(crate) struct PltGotSection {
    got_base: VmAddr,
    got_plt_base: VmAddr,
    plt_base: VmAddr,
    got_idx: usize,
    got_plt_idx: usize,
    plt_idx: usize,
    got_map: HashMap<ObjectRelocKey, usize>,
    plt_map: HashMap<ObjectRelocKey, usize>,
}

pub(crate) struct UsizeEntry<'entry>(&'entry mut usize);

impl UsizeEntry<'_> {
    pub(crate) fn update(&mut self, value: VmAddr) {
        *self.0 = value.get();
    }

    pub(crate) fn get_addr(&self) -> VmAddr {
        VmAddr::from_ptr(self.0 as *const _)
    }
}

pub(crate) enum GotEntry<'got> {
    Occupied(VmAddr),
    Vacant(UsizeEntry<'got>),
}

pub(crate) enum PltEntry<'plt> {
    Occupied(VmAddr),
    Vacant {
        plt: &'plt mut [u8],
        got: UsizeEntry<'plt>,
    },
}

/// Relocation identity used to deduplicate object GOT/PLT entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ObjectRelocKey {
    r_type: crate::elf::ElfRelocationType,
    r_sym: usize,
    addend: isize,
}

impl ObjectRelocKey {
    #[inline]
    pub(crate) fn new<Arch: RelocationArch>(rel: &ElfRelType<Arch>) -> Self {
        let addend = if <ElfRelType<Arch> as ElfRelEntry<Arch::Layout>>::HAS_IMPLICIT_ADDEND {
            0
        } else {
            rel.r_addend(VmAddr::null())
        };
        Self {
            r_type: rel.r_type(),
            r_sym: rel.r_symbol(),
            addend,
        }
    }
}

impl PltGotSection {
    fn count_needed_entries<Arch: ObjectRelocationArch>(
        shdrs: &[ElfShdr<Arch::Layout>],
        object: &impl ElfReader,
    ) -> Result<(usize, usize)> {
        let mut got_set = HashSet::new();
        let mut got_plt_set = HashSet::new();
        let mut scratch =
            AlignedBytes::with_len(0).expect("failed to initialize relocation buffer");

        for shdr in shdrs
            .iter()
            .filter(|s| matches!(s.section_type(), ElfSectionType::REL | ElfSectionType::RELA))
        {
            let size = shdr.sh_size();
            if size == 0 {
                continue;
            }

            object.with_bytes::<ElfRelType<Arch>, _, _>(
                shdr.sh_offset(),
                size,
                &mut scratch,
                |relocations| {
                    for rel_entry in relocations {
                        let r_type = rel_entry.r_type();
                        let key = ObjectRelocKey::new::<Arch>(rel_entry);

                        if Arch::object_needs_got(r_type) {
                            got_set.insert(key);
                        }
                        if Arch::object_needs_plt(r_type) {
                            got_plt_set.insert(key);
                        }
                    }
                    Ok(())
                },
            )?;
        }

        Ok((got_set.len(), got_plt_set.len()))
    }

    fn create_got_shdr<L: ElfLayout>(elem_cnt: usize) -> ElfShdr<L> {
        create_pltgot_shdr(
            ElfSectionFlags::ALLOC | ElfSectionFlags::WRITE,
            elem_cnt,
            size_of::<usize>(),
        )
    }

    fn create_got_plt_shdr<L: ElfLayout>(elem_cnt: usize) -> ElfShdr<L> {
        create_pltgot_shdr(
            ElfSectionFlags::ALLOC | ElfSectionFlags::WRITE,
            elem_cnt,
            size_of::<usize>(),
        )
    }

    fn create_plt_shdr<L: ElfLayout>(elem_cnt: usize) -> ElfShdr<L> {
        let mut shdr = create_pltgot_shdr(
            ElfSectionFlags::ALLOC | ElfSectionFlags::EXECINSTR,
            elem_cnt,
            PLT_ENTRY_SIZE,
        );
        shdr.set_sh_addralign(size_of::<usize>());
        shdr
    }

    fn new(got_base: VmAddr, got_plt_base: VmAddr, plt_base: VmAddr) -> Self {
        Self {
            got_idx: 0,
            got_plt_idx: 0,
            plt_idx: 0,
            got_map: HashMap::new(),
            plt_map: HashMap::new(),
            got_base,
            got_plt_base,
            plt_base,
        }
    }

    pub(crate) fn rebase(&mut self, base: VmAddr) {
        self.got_base = self.got_base + VmOffset::new(base.get());
        self.got_plt_base = self.got_plt_base + VmOffset::new(base.get());
        self.plt_base = self.plt_base + VmOffset::new(base.get());
    }

    pub(crate) fn add_got_entry(&mut self, key: ObjectRelocKey) -> GotEntry<'_> {
        let base = self.got_base;
        let ent_size = size_of::<usize>();
        match self.got_map.entry(key) {
            Entry::Occupied(mut entry) => {
                GotEntry::Occupied(base + VmOffset::new(*entry.get_mut() * ent_size))
            }
            Entry::Vacant(entry) => {
                let idx = *entry.insert(self.got_idx);
                self.got_idx += 1;
                GotEntry::Vacant(unsafe {
                    UsizeEntry(&mut *(base + VmOffset::new(idx * ent_size)).as_mut_ptr())
                })
            }
        }
    }

    pub(crate) fn add_plt_entry(&mut self, key: ObjectRelocKey) -> PltEntry<'_> {
        let plt_base = self.plt_base;
        let got_plt_base = self.got_plt_base;
        let plt_ent_size = PLT_ENTRY_SIZE;
        let got_ent_size = size_of::<usize>();
        match self.plt_map.entry(key) {
            Entry::Occupied(mut entry) => {
                PltEntry::Occupied(plt_base + VmOffset::new(*entry.get_mut() * plt_ent_size))
            }
            Entry::Vacant(entry) => {
                let plt_idx = *entry.insert(self.plt_idx);
                self.plt_idx += 1;

                let got_idx = self.got_plt_idx;
                self.got_plt_idx += 1;

                let plt = unsafe {
                    core::slice::from_raw_parts_mut(
                        (plt_base + VmOffset::new(plt_idx * plt_ent_size)).as_mut_ptr(),
                        plt_ent_size,
                    )
                };

                plt.copy_from_slice(&PLT_ENTRY);

                PltEntry::Vacant {
                    plt,
                    got: unsafe {
                        UsizeEntry(
                            &mut *(got_plt_base + VmOffset::new(got_idx * got_ent_size))
                                .as_mut_ptr(),
                        )
                    },
                }
            }
        }
    }
}

struct SectionUnit<'shdr, L: ElfLayout> {
    content_sections: Vec<&'shdr mut ElfShdr<L>>,
    zero_sections: Vec<&'shdr mut ElfShdr<L>>,
}

impl<'shdr, L: ElfLayout> SectionUnit<'shdr, L> {
    fn new() -> Self {
        Self {
            content_sections: Vec::new(),
            zero_sections: Vec::new(),
        }
    }

    fn add_section(&mut self, shdr: &'shdr mut ElfShdr<L>) {
        if shdr.section_type() == ElfSectionType::NOBITS {
            self.zero_sections.push(shdr);
        } else {
            self.content_sections.push(shdr);
        }
    }

    fn create_segment(&mut self, base_offset: &mut usize, page_size: usize) -> Option<ElfSegment> {
        let first_shdr = self
            .content_sections
            .first()
            .or(self.zero_sections.first())?;

        let prot = section_prot(first_shdr.flags());
        let segment_start = *base_offset;

        let mut current_offset = segment_start;
        let mut map_info = Vec::new();
        for shdr in &mut self.content_sections {
            if shdr.sh_size() == 0 {
                continue;
            }
            current_offset = roundup(current_offset, shdr.sh_addralign());
            shdr.set_sh_addr(current_offset);
            map_info.push(FileMapInfo {
                filesz: shdr.sh_size(),
                offset: shdr.sh_offset(),
                start: current_offset - segment_start,
            });
            current_offset += shdr.sh_size();
        }

        if map_info.len() == 1 {
            let info = &mut map_info[0];
            let file_offset = rounddown(info.offset, page_size);
            let align_len = info.offset - file_offset;

            let shdr = self
                .content_sections
                .iter_mut()
                .find(|shdr| shdr.sh_offset() == info.offset)
                .unwrap();

            shdr.add_sh_addr(align_len);
            info.filesz += align_len;
            info.offset = file_offset;
            current_offset += align_len;
        }

        let content_size = current_offset - segment_start;

        for shdr in &mut self.zero_sections {
            current_offset = roundup(current_offset, shdr.sh_addralign());
            shdr.set_sh_addr(current_offset);
            current_offset += shdr.sh_size();
        }

        let unaligned_total_size = current_offset - segment_start;
        let total_size = roundup(unaligned_total_size, page_size);

        if total_size == 0 {
            return None;
        }

        *base_offset += total_size;
        Some(ElfSegment {
            offset: VmOffset::new(segment_start),
            prot,
            len: total_size,
            page_size,
            content_size,
            zero_size: unaligned_total_size - content_size,
            need_copy: false,
            flags: MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            map_info,
            from_relocatable: true,
        })
    }
}
