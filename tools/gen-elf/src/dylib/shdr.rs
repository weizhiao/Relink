use crate::common::SectionKind;
use crate::dylib::{
    DYN_SIZE_32, DYN_SIZE_64, HASH_SIZE, REL_SIZE_32, REL_SIZE_64, RELA_SIZE_32, RELA_SIZE_64,
    SYM_SIZE_32, SYM_SIZE_64, StringTable, layout::ElfLayout,
};
use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};
use object::elf::*;
use std::collections::HashMap;

#[derive(Clone, Copy)]
pub(crate) struct SectionHeader {
    pub(crate) name_off: u32,
    pub(crate) shtype: SectionKind,
    pub(crate) addr: u64,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) addralign: u64,
}

impl SectionKind {
    fn as_str(&self) -> &'static str {
        match self {
            SectionKind::Null => ".null",
            SectionKind::DynStr => ".dynstr",
            SectionKind::DynSym => ".dynsym",
            SectionKind::RelaDyn => ".rela.dyn",
            SectionKind::RelaPlt => ".rela.plt",
            SectionKind::RelDyn => ".rel.dyn",
            SectionKind::RelPlt => ".rel.plt",
            SectionKind::Dynamic => ".dynamic",
            SectionKind::Hash => ".hash",
            SectionKind::ShStrTab => ".shstrtab",
            SectionKind::Plt => ".plt",
            SectionKind::Text => ".text",
            SectionKind::Data => ".data",
            SectionKind::Got => ".got",
            SectionKind::GotPlt => ".got.plt",
            SectionKind::Tls => ".tdata",
        }
    }

    fn shtype(&self) -> u32 {
        match self {
            SectionKind::Null => SHT_NULL,
            SectionKind::DynStr | SectionKind::ShStrTab => SHT_STRTAB,
            SectionKind::DynSym => SHT_DYNSYM,
            SectionKind::RelaDyn | SectionKind::RelaPlt => SHT_RELA,
            SectionKind::RelDyn | SectionKind::RelPlt => SHT_REL,
            SectionKind::Dynamic => SHT_DYNAMIC,
            SectionKind::Hash => SHT_HASH,
            SectionKind::Plt | SectionKind::Text | SectionKind::Data => SHT_PROGBITS,
            SectionKind::Got | SectionKind::GotPlt => SHT_PROGBITS,
            SectionKind::Tls => SHT_PROGBITS,
        }
    }

    fn flags(&self) -> u64 {
        match self {
            SectionKind::Plt | SectionKind::Text => (SHF_ALLOC | SHF_EXECINSTR) as u64,
            SectionKind::Data | SectionKind::Got | SectionKind::GotPlt => {
                (SHF_ALLOC | SHF_WRITE) as u64
            }
            SectionKind::Tls => (SHF_ALLOC | SHF_WRITE | SHF_TLS) as u64,
            SectionKind::Dynamic => (SHF_ALLOC | SHF_WRITE) as u64,
            SectionKind::DynStr
            | SectionKind::DynSym
            | SectionKind::RelaDyn
            | SectionKind::RelaPlt
            | SectionKind::RelDyn
            | SectionKind::RelPlt
            | SectionKind::Hash => SHF_ALLOC as u64,
            _ => 0,
        }
    }

    fn entsize(&self, is_64: bool) -> u64 {
        match self {
            SectionKind::DynSym => {
                if is_64 {
                    SYM_SIZE_64
                } else {
                    SYM_SIZE_32
                }
            }
            SectionKind::RelaDyn | SectionKind::RelaPlt => {
                if is_64 {
                    RELA_SIZE_64
                } else {
                    RELA_SIZE_32
                }
            }
            SectionKind::RelDyn | SectionKind::RelPlt => {
                if is_64 {
                    REL_SIZE_64
                } else {
                    REL_SIZE_32
                }
            }
            SectionKind::Dynamic => {
                if is_64 {
                    DYN_SIZE_64
                } else {
                    DYN_SIZE_32
                }
            }
            SectionKind::Hash => HASH_SIZE,
            SectionKind::Got => {
                if is_64 {
                    8
                } else {
                    4
                }
            }
            SectionKind::Null => 0,
            _ => 0,
        }
    }

    fn info(&self, map: &HashMap<SectionKind, usize>) -> u32 {
        match self {
            SectionKind::DynSym => 1, // First non-local symbol
            SectionKind::RelaPlt | SectionKind::RelPlt => {
                *map.get(&SectionKind::Plt).unwrap_or(&0) as u32
            }
            SectionKind::Null => 0,
            _ => 0,
        }
    }

    fn link(&self, map: &HashMap<SectionKind, usize>) -> u32 {
        match self {
            SectionKind::DynSym => *map.get(&SectionKind::DynStr).unwrap() as u32,
            SectionKind::RelaDyn | SectionKind::RelDyn => {
                *map.get(&SectionKind::DynSym).unwrap() as u32
            }
            SectionKind::RelaPlt | SectionKind::RelPlt => {
                *map.get(&SectionKind::DynSym).unwrap() as u32
            }
            SectionKind::Dynamic => *map.get(&SectionKind::DynStr).unwrap() as u32,
            SectionKind::Hash => *map.get(&SectionKind::DynSym).unwrap() as u32,
            SectionKind::Null => 0,
            _ => 0,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SectionId(usize);

pub(crate) struct SectionAllocator {
    data: Vec<Vec<u8>>,
}

impl SectionAllocator {
    pub(crate) fn new() -> Self {
        Self { data: vec![] }
    }

    pub(crate) fn allocate(&mut self, size: usize) -> SectionId {
        let id = self.data.len();
        self.data.push(vec![0u8; size]);
        SectionId(id)
    }

    pub(crate) fn allocate_with_data(&mut self, content: Vec<u8>) -> SectionId {
        let id = self.data.len();
        self.data.push(content);
        SectionId(id)
    }

    pub(crate) fn get_mut(&mut self, id: &SectionId) -> &mut Vec<u8> {
        &mut self.data[id.0]
    }

    pub(crate) fn get(&self, id: &SectionId) -> &Vec<u8> {
        &self.data[id.0]
    }
}

#[derive(Clone)]
pub(crate) struct Section {
    pub header: SectionHeader,
    pub data: SectionId,
}

pub(crate) struct ShdrManager {
    shdrs: Vec<Section>,
    rx_secs: Option<Vec<Section>>,
    r_secs: Option<Vec<Section>>,
    rw_secs: Option<Vec<Section>>,
}

impl ShdrManager {
    pub(crate) fn new() -> Self {
        Self {
            shdrs: vec![],
            rx_secs: None,
            r_secs: None,
            rw_secs: None,
        }
    }

    pub(crate) fn add_section(&mut self, header: SectionHeader, data: SectionId) {
        self.shdrs.push(Section { header, data });
    }

    pub(crate) fn layout(&mut self, layout: &mut ElfLayout) {
        // 1. Sort sections by flags to group them into segments
        // Order: R (Read-only) -> RX (Code) -> RW (Read-write) -> Non-Alloc (Metadata)
        self.shdrs.sort_by_key(|s| {
            let flags = s.header.shtype.flags();
            if flags & (SHF_ALLOC as u64) != 0 {
                if flags & (SHF_WRITE as u64) == 0 && flags & (SHF_EXECINSTR as u64) == 0 {
                    0 // R: .hash, .dynsym, .dynstr, .rela.dyn
                } else if flags & (SHF_EXECINSTR as u64) != 0 {
                    1 // RX: .text, .plt
                } else {
                    2 // RW: .dynamic, .got, .data
                }
            } else {
                3 // Non-Alloc: .symtab, .strtab, .shstrtab
            }
        });

        // 2. Assign offsets and virtual addresses
        let mut last_group = None;
        for sec in &mut self.shdrs {
            let flags = sec.header.shtype.flags();
            let current_group = if flags & (SHF_ALLOC as u64) != 0 {
                if flags & (SHF_WRITE as u64) == 0 && flags & (SHF_EXECINSTR as u64) == 0 {
                    Some(0)
                } else if flags & (SHF_EXECINSTR as u64) != 0 {
                    Some(1)
                } else {
                    Some(2)
                }
            } else {
                None
            };

            // If we enter a new allocatable group, align to page boundary
            if current_group != last_group && current_group.is_some() {
                layout.align_to_page();
            }
            last_group = current_group;

            let (off, vaddr) = layout.add_section(sec.header.size, sec.header.addralign);
            sec.header.offset = off;
            if flags & (SHF_ALLOC as u64) != 0 {
                sec.header.addr = vaddr;
            } else {
                sec.header.addr = 0;
            }
        }

        // 3. Group sections into segments for later use
        let mut rx = vec![];
        let mut r = vec![];
        let mut rw = vec![];

        for sec in &self.shdrs {
            let flags = sec.header.shtype.flags();
            if flags & (SHF_ALLOC as u64) != 0 {
                if flags & (SHF_EXECINSTR as u64) != 0 {
                    rx.push(sec.clone());
                } else if flags & (SHF_WRITE as u64) == 0 {
                    r.push(sec.clone());
                } else {
                    rw.push(sec.clone());
                }
            }
        }

        self.rx_secs = Some(rx);
        self.r_secs = Some(r);
        self.rw_secs = Some(rw);
    }

    pub(crate) fn create_shstrtab_section(&mut self, allocator: &mut SectionAllocator) {
        let mut shstrtab = StringTable::new();
        let mut name_to_off = HashMap::new();

        for sec in &mut self.shdrs {
            let name = sec.header.shtype.as_str();
            if let Some(&off) = name_to_off.get(name) {
                sec.header.name_off = off;
            } else {
                let off = shstrtab.add(name);
                name_to_off.insert(name, off);
                sec.header.name_off = off;
            }
        }

        // Add .shstrtab itself
        let shstrtab_name = SectionKind::ShStrTab.as_str();
        let shstrtab_off = shstrtab.add(shstrtab_name);

        let shstrtab_data = shstrtab.data();
        let shstrtab_id = allocator.allocate(shstrtab_data.len());
        allocator
            .get_mut(&shstrtab_id)
            .copy_from_slice(shstrtab_data);

        self.add_section(
            SectionHeader {
                name_off: shstrtab_off,
                shtype: SectionKind::ShStrTab,
                addr: 0,
                offset: 0,
                size: shstrtab_data.len() as u64,
                addralign: 1,
            },
            shstrtab_id,
        );
    }

    pub(crate) fn get_shdr_map(&self) -> HashMap<SectionKind, usize> {
        let mut map = HashMap::new();
        for (i, sec) in self.shdrs.iter().enumerate() {
            map.insert(sec.header.shtype, i + 1);
        }
        map
    }

    pub(crate) fn get_vaddr(&self, shtype: SectionKind) -> u64 {
        self.shdrs
            .iter()
            .find(|s| s.header.shtype == shtype)
            .map(|s| s.header.addr)
            .unwrap_or(0)
    }

    pub(crate) fn get_size(&self, shtype: SectionKind) -> u64 {
        self.shdrs
            .iter()
            .find(|s| s.header.shtype == shtype)
            .map(|s| s.header.size)
            .unwrap_or(0)
    }

    pub(crate) fn get_data_id(&self, shtype: SectionKind) -> SectionId {
        self.shdrs
            .iter()
            .find(|s| s.header.shtype == shtype)
            .map(|s| s.data.clone())
            .unwrap()
    }

    pub(crate) fn get_shdr_count(&self) -> usize {
        self.shdrs.len()
    }

    pub(crate) fn get_sections(&self) -> &[Section] {
        &self.shdrs
    }

    pub(crate) fn get_phnum(&self) -> u16 {
        let mut count = 1; // PT_PHDR
        let mut has_rx = false;
        let mut has_r = false;
        let mut has_rw = false;
        let mut has_dynamic = false;
        let mut has_tls = false;

        for sec in &self.shdrs {
            let flags = sec.header.shtype.flags();
            if flags & (SHF_ALLOC as u64) != 0 {
                if flags & (SHF_EXECINSTR as u64) != 0 {
                    has_rx = true;
                } else if flags & (SHF_WRITE as u64) == 0 {
                    has_r = true;
                } else {
                    has_rw = true;
                }
            }
            if sec.header.shtype == SectionKind::Dynamic {
                has_dynamic = true;
            }
            if sec.header.shtype == SectionKind::Tls {
                has_tls = true;
            }
        }

        if has_rx {
            count += 1;
        }
        if has_r {
            count += 1;
        }
        if has_rw {
            count += 1;
        }
        if has_dynamic {
            count += 1;
        }
        if has_tls {
            count += 1;
        }
        count
    }

    pub(crate) fn write_shdrs<W: std::io::Write>(&self, mut writer: W, is_64: bool) -> Result<()> {
        let mut map = HashMap::new();
        for (i, sec) in self.shdrs.iter().enumerate() {
            map.insert(sec.header.shtype, i + 1);
        }

        // Null section
        if is_64 {
            for _ in 0..64 {
                writer.write_u8(0)?;
            }
        } else {
            for _ in 0..40 {
                writer.write_u8(0)?;
            }
        }

        for sec in &self.shdrs {
            let h = &sec.header;
            if is_64 {
                writer.write_u32::<LittleEndian>(h.name_off)?;
                writer.write_u32::<LittleEndian>(h.shtype.shtype())?;
                writer.write_u64::<LittleEndian>(h.shtype.flags())?;
                writer.write_u64::<LittleEndian>(h.addr)?;
                writer.write_u64::<LittleEndian>(h.offset)?;
                writer.write_u64::<LittleEndian>(h.size)?;
                writer.write_u32::<LittleEndian>(h.shtype.link(&map))?;
                writer.write_u32::<LittleEndian>(h.shtype.info(&map))?;
                writer.write_u64::<LittleEndian>(h.addralign)?;
                writer.write_u64::<LittleEndian>(h.shtype.entsize(is_64))?;
            } else {
                writer.write_u32::<LittleEndian>(h.name_off)?;
                writer.write_u32::<LittleEndian>(h.shtype.shtype())?;
                writer.write_u32::<LittleEndian>(h.shtype.flags() as u32)?;
                writer.write_u32::<LittleEndian>(h.addr as u32)?;
                writer.write_u32::<LittleEndian>(h.offset as u32)?;
                writer.write_u32::<LittleEndian>(h.size as u32)?;
                writer.write_u32::<LittleEndian>(h.shtype.link(&map))?;
                writer.write_u32::<LittleEndian>(h.shtype.info(&map))?;
                writer.write_u32::<LittleEndian>(h.addralign as u32)?;
                writer.write_u32::<LittleEndian>(h.shtype.entsize(is_64) as u32)?;
            }
        }
        Ok(())
    }

    pub(crate) fn write_phdrs<W: std::io::Write>(
        &self,
        mut writer: W,
        is_64: bool,
        page_size: u64,
    ) -> Result<()> {
        let rx_secs = self
            .rx_secs
            .as_ref()
            .expect("layout must be called before write_phdrs");
        let r_secs = self
            .r_secs
            .as_ref()
            .expect("layout must be called before write_phdrs");
        let rw_secs = self
            .rw_secs
            .as_ref()
            .expect("layout must be called before write_phdrs");

        // 0. PT_PHDR
        let ph_size = (if is_64 { 56 } else { 32 }) * self.get_phnum() as u64;
        self.write_phdr(
            &mut writer,
            is_64,
            PT_PHDR,
            PF_R,
            if is_64 { 64 } else { 52 },
            if is_64 { 64 } else { 52 },
            ph_size,
            ph_size,
            8,
        )?;

        // 1. R Segment
        if let (Some(first), Some(last)) = (r_secs.first(), r_secs.last()) {
            // Ensure R segment starts from 0 to cover EHDR and PHDRs
            let p_offset = 0;
            let p_vaddr = first.header.addr - first.header.offset;
            let p_filesz = (last.header.offset + last.header.size) - p_offset;

            self.write_phdr(
                &mut writer,
                is_64,
                PT_LOAD,
                PF_R,
                p_offset,
                p_vaddr,
                p_filesz,
                p_filesz,
                page_size,
            )?;
        }

        // 2. RX Segment
        if let (Some(first), Some(last)) = (rx_secs.first(), rx_secs.last()) {
            let p_offset = first.header.offset;
            let p_vaddr = first.header.addr;
            let p_filesz = (last.header.offset + last.header.size) - p_offset;

            self.write_phdr(
                &mut writer,
                is_64,
                PT_LOAD,
                PF_R | PF_X,
                p_offset,
                p_vaddr,
                p_filesz,
                p_filesz,
                page_size,
            )?;
        }

        // 3. RW Segment
        if let (Some(first), Some(last)) = (rw_secs.first(), rw_secs.last()) {
            let p_offset = first.header.offset;
            let p_vaddr = first.header.addr;
            let p_filesz = (last.header.offset + last.header.size) - p_offset;

            self.write_phdr(
                &mut writer,
                is_64,
                PT_LOAD,
                PF_R | PF_W,
                p_offset,
                p_vaddr,
                p_filesz,
                p_filesz,
                page_size,
            )?;
        }

        // 4. PT_DYNAMIC
        if let Some(dyn_sec) = self
            .shdrs
            .iter()
            .find(|s| s.header.shtype == SectionKind::Dynamic)
        {
            self.write_phdr(
                &mut writer,
                is_64,
                PT_DYNAMIC,
                PF_R | PF_W,
                dyn_sec.header.offset,
                dyn_sec.header.addr,
                dyn_sec.header.size,
                dyn_sec.header.size,
                8,
            )?;
        }

        // 5. PT_TLS
        if let Some(tls_sec) = self
            .shdrs
            .iter()
            .find(|s| s.header.shtype == SectionKind::Tls)
        {
            self.write_phdr(
                &mut writer,
                is_64,
                PT_TLS,
                PF_R,
                tls_sec.header.offset,
                tls_sec.header.addr,
                tls_sec.header.size,
                tls_sec.header.size,
                if is_64 { 8 } else { 4 },
            )?;
        }

        Ok(())
    }

    fn write_phdr<W: std::io::Write>(
        &self,
        mut writer: W,
        is_64: bool,
        p_type: u32,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
        p_align: u64,
    ) -> Result<()> {
        if is_64 {
            writer.write_u32::<LittleEndian>(p_type)?;
            writer.write_u32::<LittleEndian>(p_flags)?;
            writer.write_u64::<LittleEndian>(p_offset)?;
            writer.write_u64::<LittleEndian>(p_vaddr)?;
            writer.write_u64::<LittleEndian>(p_vaddr)?; // p_paddr
            writer.write_u64::<LittleEndian>(p_filesz)?;
            writer.write_u64::<LittleEndian>(p_memsz)?;
            writer.write_u64::<LittleEndian>(p_align)?;
        } else {
            writer.write_u32::<LittleEndian>(p_type)?;
            writer.write_u32::<LittleEndian>(p_offset as u32)?;
            writer.write_u32::<LittleEndian>(p_vaddr as u32)?;
            writer.write_u32::<LittleEndian>(p_vaddr as u32)?; // p_paddr
            writer.write_u32::<LittleEndian>(p_filesz as u32)?;
            writer.write_u32::<LittleEndian>(p_memsz as u32)?;
            writer.write_u32::<LittleEndian>(p_flags)?;
            writer.write_u32::<LittleEndian>(p_align as u32)?;
        }
        Ok(())
    }
}
