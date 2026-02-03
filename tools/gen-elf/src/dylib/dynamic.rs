use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};
use object::elf::*;

use crate::Arch;
use crate::common::SectionKind;
use crate::dylib::reloc::RelocMetaData;
use crate::dylib::shdr::{Section, SectionAllocator, SectionHeader, SectionId, ShdrManager};
use crate::dylib::{
    REL_SIZE_32, REL_SIZE_64, RELA_SIZE_32, RELA_SIZE_64, SYM_SIZE_32, SYM_SIZE_64,
};

#[derive(Debug, Clone)]
struct DynamicEntry {
    tag: i64,
    value: u64,
}

pub(crate) struct DynamicMetadata {
    arch: Arch,
    dyn_entries: Vec<DynamicEntry>,
    dynamic_id: SectionId,
}

impl DynamicMetadata {
    pub(crate) fn new(arch: Arch, sections: &[Section], allocator: &mut SectionAllocator) -> Self {
        let dynamic_id = allocator.allocate(0);
        let mut instance = Self {
            arch,
            dyn_entries: vec![],
            dynamic_id,
        };
        instance.init_from_sections(sections);
        instance
    }

    pub(crate) fn create_section(&self, sections: &mut Vec<Section>) {
        let dyn_size = self.size();
        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: SectionKind::Dynamic,
                addr: 0,
                offset: 0,
                size: dyn_size,
                addralign: 8,
            },
            data: self.dynamic_id,
        });
    }

    fn init_from_sections(&mut self, sections: &[Section]) {
        let is_64 = self.arch.is_64();
        let is_rela = self.arch.is_rela();
        for sec in sections {
            let vaddr = sec.header.addr;
            let size = sec.header.size;
            match sec.header.shtype {
                SectionKind::DynStr => {
                    self.add_entry(DT_STRTAB as i64, vaddr);
                    self.add_entry(DT_STRSZ as i64, size);
                }
                SectionKind::DynSym => {
                    self.add_entry(DT_SYMTAB as i64, vaddr);
                    self.add_entry(
                        DT_SYMENT as i64,
                        if is_64 { SYM_SIZE_64 } else { SYM_SIZE_32 },
                    );
                }
                SectionKind::Hash => {
                    self.add_entry(DT_HASH as i64, vaddr);
                }
                SectionKind::Got => {
                    self.add_entry(DT_PLTGOT as i64, vaddr);
                }
                SectionKind::RelaDyn => {
                    self.add_entry(DT_RELA as i64, vaddr);
                    self.add_entry(DT_RELASZ as i64, size);
                    self.add_entry(
                        DT_RELAENT as i64,
                        if is_64 { RELA_SIZE_64 } else { RELA_SIZE_32 },
                    );
                    self.add_entry(DT_RELACOUNT as i64, 0);
                }
                SectionKind::RelDyn => {
                    self.add_entry(DT_REL as i64, vaddr);
                    self.add_entry(DT_RELSZ as i64, size);
                    self.add_entry(
                        DT_RELENT as i64,
                        if is_64 { REL_SIZE_64 } else { REL_SIZE_32 },
                    );
                    self.add_entry(DT_RELCOUNT as i64, 0);
                }
                SectionKind::RelaPlt | SectionKind::RelPlt => {
                    self.add_entry(DT_JMPREL as i64, vaddr);
                    self.add_entry(DT_PLTRELSZ as i64, size);
                    self.add_entry(
                        DT_PLTREL as i64,
                        if is_rela {
                            DT_RELA as u64
                        } else {
                            DT_REL as u64
                        },
                    );
                }
                _ => {}
            }
        }
        self.add_entry(DT_NULL as i64, 0);
    }

    pub(crate) fn add_entry(&mut self, tag: i64, value: u64) {
        self.dyn_entries.push(DynamicEntry { tag, value });
    }

    pub(crate) fn update_entry(&mut self, tag: i64, value: u64) {
        if let Some(entry) = self.dyn_entries.iter_mut().find(|e| e.tag == tag) {
            entry.value = value;
        } else {
            // Insert before DT_NULL if it exists
            if let Some(pos) = self
                .dyn_entries
                .iter()
                .position(|e| e.tag == DT_NULL as i64)
            {
                self.dyn_entries.insert(pos, DynamicEntry { tag, value });
            } else {
                self.add_entry(tag, value);
            }
        }
    }

    pub(crate) fn patch_dynamic(
        &mut self,
        shdr_manager: &ShdrManager,
        reloc: &RelocMetaData,
        allocator: &mut SectionAllocator,

        got_plt_vaddr: u64,
    ) -> Result<()> {
        let is_64 = self.arch.is_64();
        let is_rela = self.arch.is_rela();
        self.update_entry(
            DT_STRTAB as i64,
            shdr_manager.get_vaddr(SectionKind::DynStr),
        );
        self.update_entry(
            DT_SYMTAB as i64,
            shdr_manager.get_vaddr(SectionKind::DynSym),
        );
        self.update_entry(DT_HASH as i64, shdr_manager.get_vaddr(SectionKind::Hash));
        self.update_entry(DT_PLTGOT as i64, got_plt_vaddr);
        if is_rela {
            let rela_dyn_vaddr = shdr_manager.get_vaddr(SectionKind::RelaDyn);
            let rela_dyn_size = shdr_manager.get_size(SectionKind::RelaDyn);
            self.update_entry(DT_RELA as i64, rela_dyn_vaddr);
            self.update_entry(DT_RELASZ as i64, rela_dyn_size);

            let rela_plt_vaddr = shdr_manager.get_vaddr(SectionKind::RelaPlt);
            let rela_plt_size = shdr_manager.get_size(SectionKind::RelaPlt);
            self.update_entry(DT_JMPREL as i64, rela_plt_vaddr);
            self.update_entry(DT_PLTRELSZ as i64, rela_plt_size);
            self.update_entry(DT_RELACOUNT as i64, reloc.relative_count() as u64);
        } else {
            let rel_dyn_vaddr = shdr_manager.get_vaddr(SectionKind::RelDyn);
            let rel_dyn_size = shdr_manager.get_size(SectionKind::RelDyn);
            self.update_entry(DT_REL as i64, rel_dyn_vaddr);
            self.update_entry(DT_RELSZ as i64, rel_dyn_size);

            let rel_plt_vaddr = shdr_manager.get_vaddr(SectionKind::RelPlt);
            let rel_plt_size = shdr_manager.get_size(SectionKind::RelPlt);
            self.update_entry(DT_JMPREL as i64, rel_plt_vaddr);
            self.update_entry(DT_PLTRELSZ as i64, rel_plt_size);
            self.update_entry(DT_RELCOUNT as i64, reloc.relative_count() as u64);
        }
        let dyn_id = shdr_manager.get_data_id(SectionKind::Dynamic);
        self.write_to_vec(allocator.get_mut(&dyn_id), is_64)?;
        Ok(())
    }

    pub(crate) fn size(&self) -> u64 {
        let entry_size = if self.arch.is_64() { 16 } else { 8 };
        (self.dyn_entries.len() as u64) * entry_size
    }

    pub(crate) fn write<W: std::io::Write>(&self, mut writer: W, is_64: bool) -> Result<()> {
        for entry in &self.dyn_entries {
            if is_64 {
                writer.write_i64::<LittleEndian>(entry.tag)?;
                writer.write_u64::<LittleEndian>(entry.value)?;
            } else {
                writer.write_i32::<LittleEndian>(entry.tag as i32)?;
                writer.write_u32::<LittleEndian>(entry.value as u32)?;
            }
        }
        Ok(())
    }
}

impl DynamicMetadata {
    pub(crate) fn write_to_vec(&self, buf: &mut Vec<u8>, is_64: bool) -> Result<()> {
        buf.clear();
        self.write(buf, is_64)
    }
}
