use crate::common::{RelocEntry, RelocType, SectionKind};
use crate::dylib::symtab::IFUNC_RESOLVER_NAME;
use crate::{
    Arch,
    dylib::{
        RelocationInfo,
        shdr::{Section, SectionAllocator, SectionHeader, SectionId, ShdrManager},
        symtab::SymTabMetadata,
    },
};
use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

pub(crate) struct RelocMetaData {
    arch: Arch,
    relocs: Vec<Reloc>,
    relative_count: usize,
    got_count: usize,
    copy_count: usize,
    plt_count: usize,
    irelative_count: usize,
    total_copy_size: u64,
    rel_dyn_id: SectionId,
    rel_plt_id: SectionId,
    got_id: SectionId,
    got_plt_id: SectionId,
}

impl RelocMetaData {
    pub(crate) fn preprocess(arch: Arch, raw: &[RelocEntry]) -> Vec<RelocEntry> {
        let mut relocs = raw.to_vec();
        if relocs.iter().any(|r| r.r_type.is_tls_reloc(arch))
            && !relocs
                .iter()
                .any(|r| r.symbol_name == crate::dylib::symtab::TLS_GET_ADDR_NAME)
        {
            relocs.push(RelocEntry::jump_slot(
                crate::dylib::symtab::TLS_GET_ADDR_NAME,
                arch,
            ));
        }
        relocs
    }

    pub(crate) fn new(
        arch: Arch,
        raw: &[RelocEntry],
        symbols: &SymTabMetadata,
        allocator: &mut SectionAllocator,
    ) -> Result<Self> {
        let mut relocs = Vec::new();

        // Process relocations in passes: RELATIVE first, then GOT, then COPY, then PLT
        let mut relative_relocs = Vec::new();
        let mut got_relocs = Vec::new();
        let mut copy_relocs = Vec::new();
        let mut plt_relocs = Vec::new();
        let mut irelative_relocs = Vec::new();

        for r in raw.iter() {
            if r.r_type.is_relative_reloc(arch) {
                relative_relocs.push(r);
            } else if r.r_type.is_irelative_reloc(arch) {
                irelative_relocs.push(r);
            } else if r.r_type.is_plt_reloc(arch) {
                plt_relocs.push(r);
            } else if r.r_type.is_copy_reloc(arch) {
                copy_relocs.push(r);
            } else {
                got_relocs.push(r);
            }
        }

        let relative_count = relative_relocs.len();
        let got_count = got_relocs.len();
        let copy_count = copy_relocs.len();
        let plt_count = plt_relocs.len();
        let irelative_count = irelative_relocs.len();

        let word_size = if arch.is_64() { 8 } else { 4 };

        let mut got_slot_idx = 0;
        // Process relative relocations (relative to GOT)
        for r in relative_relocs.into_iter() {
            debug_assert!(r.symbol_name.is_empty());
            relocs.push(Reloc {
                sym_idx: 0,
                offset: got_slot_idx * word_size,
                addend: r.addend,
                r_type: r.r_type,
                sym_size: 0,
            });
            got_slot_idx += 1;
        }
        // Process GOT relocations (relative to GOT)
        for r in got_relocs.into_iter() {
            let sym_idx = symbols.get_sym_idx(&r.symbol_name).unwrap() as u64;
            relocs.push(Reloc {
                sym_idx,
                offset: got_slot_idx * word_size,
                addend: r.addend,
                r_type: r.r_type,
                sym_size: 0,
            });
            got_slot_idx += 1;
        }
        // Process COPY relocations (relative to DATA)
        let mut current_copy_offset = symbols.get_data_content().len() as u64;
        let mut total_copy_size = 0;
        for r in copy_relocs {
            let sym_idx = symbols.get_sym_idx(&r.symbol_name).unwrap();
            let sym_size = symbols.get_sym_size(sym_idx);

            relocs.push(Reloc {
                sym_idx: sym_idx as u64,
                offset: current_copy_offset,
                addend: 0,
                r_type: r.r_type,
                sym_size,
            });
            current_copy_offset += sym_size;
            total_copy_size += sym_size;
        }
        // Process IRELATIVE relocations (relative to GOTPLT)
        for r in irelative_relocs.into_iter() {
            relocs.push(Reloc {
                sym_idx: 0,
                offset: got_slot_idx * word_size,
                addend: 0,
                r_type: r.r_type,
                sym_size: 0,
            });
            got_slot_idx += 1;
        }

        let mut plt_slot_idx = 3;
        // Process PLT relocations (relative to GOTPLT)
        for r in plt_relocs.into_iter() {
            let sym_idx = symbols.get_sym_idx(&r.symbol_name).unwrap() as u64;
            relocs.push(Reloc {
                sym_idx,
                offset: plt_slot_idx * word_size,
                addend: 0,
                r_type: r.r_type,
                sym_size: 0,
            });
            plt_slot_idx += 1;
        }

        let is_64 = arch.is_64();
        let is_rela = arch.is_rela();
        let entry_size = if is_64 {
            if is_rela { 24 } else { 16 }
        } else {
            if is_rela { 12 } else { 8 }
        };

        let rel_dyn_id = allocator
            .allocate((relative_count + got_count + copy_count + irelative_count) * entry_size);
        let rel_plt_id = allocator.allocate(plt_count * entry_size);

        let got_id = allocator.allocate(
            ((1 + relative_count + got_count + irelative_count) as u64 * word_size) as usize,
        );
        let got_plt_id = allocator.allocate(((3 + plt_count) as u64 * word_size) as usize);

        Ok(Self {
            arch,
            relocs,
            relative_count,
            got_count,
            copy_count,
            plt_count,
            irelative_count,
            total_copy_size,
            rel_dyn_id,
            rel_plt_id,
            got_id,
            got_plt_id,
        })
    }

    fn rel_entry_size(&self) -> usize {
        let is_64 = self.arch.is_64();
        let is_rela = self.arch.is_rela();
        if is_64 {
            if is_rela { 24 } else { 16 }
        } else {
            if is_rela { 12 } else { 8 }
        }
    }

    fn word_size(&self) -> usize {
        if self.arch.is_64() { 8 } else { 4 }
    }

    fn rel_dyn_size(&self) -> u64 {
        let entry_size = self.rel_entry_size();
        ((self.relative_count + self.got_count + self.copy_count + self.irelative_count)
            * entry_size) as u64
    }

    fn rel_plt_size(&self) -> u64 {
        let entry_size = self.rel_entry_size();
        (self.plt_count * entry_size) as u64
    }

    fn got_size(&self) -> u64 {
        let word_size = self.word_size();
        ((1 + self.relative_count + self.got_count + self.irelative_count) * word_size) as u64
    }

    fn got_plt_size(&self) -> u64 {
        let word_size = self.word_size();
        ((3 + self.plt_count) * word_size) as u64
    }

    pub(crate) fn find_tls_reloc_vaddr(&self, sym_idx: u64, shdr: &ShdrManager) -> Option<u64> {
        let got_vaddr = shdr.get_vaddr(SectionKind::Got);
        for r in &self.relocs {
            if r.sym_idx == sym_idx && r.r_type.is_tls_reloc(self.arch) {
                return Some(got_vaddr + r.offset);
            }
        }
        None
    }

    pub(crate) fn get_relocation_infos(&self) -> Vec<RelocationInfo> {
        self.relocs
            .iter()
            .map(|r| RelocationInfo {
                vaddr: r.offset,
                r_type: r.r_type.0,
                sym_idx: r.sym_idx,
                addend: r.addend,
                sym_size: r.sym_size,
            })
            .collect()
    }

    pub(crate) fn plt_relocs(&self) -> &[Reloc] {
        let start = self.relative_count + self.got_count + self.copy_count;
        let end = start + self.plt_count;
        &self.relocs[start..end]
    }

    pub(crate) fn total_copy_size(&self) -> u64 {
        self.total_copy_size
    }

    pub(crate) fn relative_count(&self) -> usize {
        self.relative_count
    }

    pub(crate) fn patch_all(
        &mut self,
        shdr_manager: &ShdrManager,
        symtab: &SymTabMetadata,
        allocator: &mut SectionAllocator,
    ) -> Result<()> {
        let plt_vaddr = shdr_manager.get_vaddr(SectionKind::Plt);
        let data_vaddr = shdr_manager.get_vaddr(SectionKind::Data);
        let got_vaddr = shdr_manager.get_vaddr(SectionKind::Got);
        let got_plt_vaddr = shdr_manager.get_vaddr(SectionKind::GotPlt);
        let dyn_vaddr = shdr_manager.get_vaddr(SectionKind::Dynamic);

        self.patch_got(allocator, self.arch, dyn_vaddr, plt_vaddr);
        self.patch_reloc(
            got_vaddr,
            got_plt_vaddr,
            data_vaddr,
            plt_vaddr,
            symtab,
            allocator,
        )?;
        Ok(())
    }

    fn patch_reloc(
        &mut self,
        got_vaddr: u64,
        got_plt_vaddr: u64,
        data_vaddr: u64,
        plt_vaddr: u64,
        symbols: &SymTabMetadata,
        allocator: &mut SectionAllocator,
    ) -> Result<()> {
        let is_64 = self.arch.is_64();
        let is_rela = self.arch.is_rela();
        allocator.get_mut(&self.rel_dyn_id).clear();
        allocator.get_mut(&self.rel_plt_id).clear();

        let plt_start =
            self.relative_count + self.got_count + self.copy_count + self.irelative_count;
        let plt_end = plt_start + self.plt_count;
        let copy_start = self.relative_count + self.got_count;
        let copy_end = copy_start + self.copy_count;

        for (i, reloc) in self.relocs.iter_mut().enumerate() {
            if reloc.r_type.is_irelative_reloc(self.arch) {
                reloc.addend = symbols
                    .get_sym_value_by_name(IFUNC_RESOLVER_NAME)
                    .expect("IFUNC resolver symbol not found")
                    as i64;
            } else {
                let sym_value = if reloc.sym_idx != 0 {
                    symbols.get_sym_value(reloc.sym_idx as usize)
                } else {
                    0
                };
                reloc.addend = crate::arch::calculate_addend(
                    self.arch,
                    reloc.r_type,
                    reloc.offset,
                    data_vaddr,
                    sym_value,
                );
            }
            let is_copy = i >= copy_start && i < copy_end;
            let is_plt = i >= plt_start && i < plt_end;

            if is_plt {
                let plt_idx = i - plt_start;
                let plt0_size = crate::arch::get_plt0_size(self.arch);
                let plt_entry_size = crate::arch::get_plt_entry_size(self.arch);
                let plt_entry_off = plt0_size + plt_idx as u64 * plt_entry_size;
                let initial_val =
                    crate::arch::get_got_plt_init_value(self.arch, plt_vaddr, plt_entry_off);
                let offset = reloc.offset as usize;
                let got = allocator.get_mut(&self.got_plt_id);
                let mut cursor = &mut got[offset..offset + (if is_64 { 8 } else { 4 })];
                if is_64 {
                    cursor.write_u64::<LittleEndian>(initial_val)?;
                } else {
                    cursor.write_u32::<LittleEndian>(initial_val as u32)?;
                }
            }

            let (base, section_id) = if i < plt_start {
                (
                    if is_copy { data_vaddr } else { got_vaddr },
                    &self.rel_dyn_id,
                )
            } else {
                (got_plt_vaddr, &self.rel_plt_id)
            };

            // For REL (non-RELA) relocations, the addend must be stored in the target location
            if !is_rela && !is_plt && !is_copy {
                let offset = reloc.offset as usize;
                // If i < copy_start, it's in GOT
                // If i >= copy_end && i < plt_start, it's IRELATIVE in GOT
                if i < copy_start || (i >= copy_end && i < plt_start) {
                    let got = allocator.get_mut(&self.got_id);
                    let mut cursor = &mut got[offset..offset + (if is_64 { 8 } else { 4 })];
                    if is_64 {
                        cursor.write_i64::<LittleEndian>(reloc.addend).unwrap();
                    } else {
                        cursor
                            .write_i32::<LittleEndian>(reloc.addend as i32)
                            .unwrap();
                    }
                }
            }

            reloc.offset += base;
            reloc.write(allocator.get_mut(section_id), is_64, is_rela)?;
        }
        Ok(())
    }

    fn patch_got(
        &self,
        allocator: &mut SectionAllocator,
        arch: crate::Arch,
        dyn_vaddr: u64,
        plt_vaddr: u64,
    ) {
        let is_64 = arch.is_64();
        let word_size = if is_64 { 8 } else { 4 };

        // .got[0] = .dynamic vaddr
        let got_data = allocator.get_mut(&self.got_id);
        if is_64 {
            let mut cursor = &mut got_data[0..8];
            cursor.write_u64::<LittleEndian>(dyn_vaddr).unwrap();
        } else {
            let mut cursor = &mut got_data[0..4];
            cursor.write_u32::<LittleEndian>(dyn_vaddr as u32).unwrap();
        }

        // .got.plt[0] = .dynamic vaddr (standard for many archs)
        let got_plt_data = allocator.get_mut(&self.got_plt_id);
        if is_64 {
            let mut cursor = &mut got_plt_data[0..8];
            cursor.write_u64::<LittleEndian>(dyn_vaddr).unwrap();
        } else {
            let mut cursor = &mut got_plt_data[0..4];
            cursor.write_u32::<LittleEndian>(dyn_vaddr as u32).unwrap();
        }

        // GOT entries for PLT in .got.plt
        let plt0_size = crate::arch::get_plt0_size(arch);
        let plt_entry_size = crate::arch::get_plt_entry_size(arch);
        let mut current_plt_off = plt0_size;

        for (i, _) in self.plt_relocs().iter().enumerate() {
            let got_off = (3 + i) * word_size;
            let initial_val =
                crate::arch::get_got_plt_init_value(arch, plt_vaddr, current_plt_off as u64);

            if is_64 {
                let mut cursor = &mut got_plt_data[got_off..got_off + 8];
                cursor.write_u64::<LittleEndian>(initial_val).unwrap();
            } else {
                let mut cursor = &mut got_plt_data[got_off..got_off + 4];
                cursor
                    .write_u32::<LittleEndian>(initial_val as u32)
                    .unwrap();
            }
            current_plt_off += plt_entry_size;
        }
    }

    pub(crate) fn create_sections(&self, sections: &mut Vec<Section>) -> Result<()> {
        let is_64 = self.arch.is_64();
        let is_rela = self.arch.is_rela();

        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: if is_rela {
                    SectionKind::RelaDyn
                } else {
                    SectionKind::RelDyn
                },
                addr: 0,
                offset: 0,
                size: self.rel_dyn_size(),
                addralign: if is_64 { 8 } else { 4 },
            },
            data: self.rel_dyn_id,
        });
        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: if is_rela {
                    SectionKind::RelaPlt
                } else {
                    SectionKind::RelPlt
                },
                addr: 0,
                offset: 0,
                size: self.rel_plt_size(),
                addralign: if is_64 { 8 } else { 4 },
            },
            data: self.rel_plt_id,
        });

        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: SectionKind::Got,
                addr: 0,
                offset: 0,
                size: self.got_size(),
                addralign: 8,
            },
            data: self.got_id,
        });

        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: SectionKind::GotPlt,
                addr: 0,
                offset: 0,
                size: self.got_plt_size(),
                addralign: 8,
            },
            data: self.got_plt_id,
        });

        Ok(())
    }
}

/// Pending relocation entry before virtual addresses are determined
#[derive(Debug)]
pub(crate) struct Reloc {
    /// Symbol index in symbol table
    sym_idx: u64,
    /// Offset within data segment
    offset: u64,
    /// Addend value
    addend: i64,
    /// Relocation type
    r_type: RelocType,
    /// Symbol size
    sym_size: u64,
}

impl Reloc {
    fn write(&self, buf: &mut Vec<u8>, is_64: bool, is_rela: bool) -> Result<()> {
        let sym_idx = self.sym_idx;
        if is_64 {
            buf.write_u64::<LittleEndian>(self.offset)?;
            let r_info = (sym_idx << 32) | (self.r_type.as_u64() & 0xffffffff);
            buf.write_u64::<LittleEndian>(r_info)?;
            if is_rela {
                buf.write_i64::<LittleEndian>(self.addend)?;
            }
        } else {
            buf.write_u32::<LittleEndian>(self.offset as u32)?;
            let r_info = ((sym_idx as u32) << 8) | (self.r_type.as_u32() & 0xff);
            buf.write_u32::<LittleEndian>(r_info)?;
            if is_rela {
                buf.write_i32::<LittleEndian>(self.addend as i32)?;
            }
        }
        Ok(())
    }
}
