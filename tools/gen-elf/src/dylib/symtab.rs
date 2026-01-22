use crate::common::{SectionKind, SymbolDesc, SymbolScope, SymbolType};
use crate::dylib::{
    StringTable,
    reloc::RelocMetaData,
    shdr::{Section, SectionAllocator, SectionHeader, SectionId, ShdrManager},
};
use crate::{Arch, RelocEntry, arch};
use byteorder::{LittleEndian, WriteBytesExt};
use object::elf::*;
use std::collections::HashMap;

const HELPER_SUFFIX: &str = "@plt_helper";
const TLS_HELPER_SUFFIX: &str = "@tls_helper";
pub(crate) const IFUNC_RESOLVER_NAME: &str = "__ifunc_resolver";
pub(crate) const TLS_GET_ADDR_NAME: &str = "__tls_get_addr";

pub(crate) struct Symbol {
    name_idx: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

impl Symbol {
    fn write(&self, buf: &mut Vec<u8>, is_64: bool) -> std::io::Result<()> {
        if is_64 {
            buf.write_u32::<LittleEndian>(self.name_idx)?;
            buf.write_u8(self.info)?;
            buf.write_u8(self.other)?;
            buf.write_u16::<LittleEndian>(self.shndx)?;
            buf.write_u64::<LittleEndian>(self.value)?;
            buf.write_u64::<LittleEndian>(self.size)?;
        } else {
            buf.write_u32::<LittleEndian>(self.name_idx)?;
            buf.write_u32::<LittleEndian>(self.value as u32)?;
            buf.write_u32::<LittleEndian>(self.size as u32)?;
            buf.write_u8(self.info)?;
            buf.write_u8(self.other)?;
            buf.write_u16::<LittleEndian>(self.shndx)?;
        }
        Ok(())
    }
}

pub(crate) struct SymTabMetadata {
    arch: Arch,
    dynstr: StringTable,
    dynsym: Vec<Symbol>,
    dynsym_shdr_types: Vec<SectionKind>,
    sym_index: HashMap<String, usize>,
    helper_index: HashMap<usize, usize>, // plt_sym_idx -> helper_sym_idx
    tls_helper_index: HashMap<usize, usize>, // tls_sym_idx -> helper_sym_idx
    symbols: Vec<SymbolDesc>,
    dynsym_id: SectionId,
    dynsym_size: u64,
    dynstr_id: SectionId,
    dynstr_size: u64,
    hash_id: SectionId,
    hash_size: u64,
    text_offset: u64,
    data_offset: u64,
    tls_offset: u64,
    plt_offset: u64,
    plt0_idx: Option<usize>,
    plt_entries: Vec<(usize, u64)>, // (plt_sym_idx, got_slot_idx)
}

impl SymTabMetadata {
    fn add_symbol(&mut self, name: &str, sym: Symbol, shdr_type: SectionKind) -> usize {
        let sym_idx = self.dynsym.len();
        self.dynsym.push(sym);
        self.dynsym_shdr_types.push(shdr_type);
        self.dynstr.add(name);
        self.sym_index.insert(name.to_string(), sym_idx);
        sym_idx
    }

    pub(crate) fn new(
        arch: Arch,
        symbols: &[SymbolDesc],
        relocs: &[RelocEntry],
        allocator: &mut SectionAllocator,
    ) -> Self {
        let dynsym_id = allocator.allocate(0);
        let dynstr_id = allocator.allocate(0);
        let hash_id = allocator.allocate(0);

        let mut symtab = Self {
            dynstr: StringTable::new(),
            dynsym: vec![],
            dynsym_shdr_types: vec![],
            sym_index: HashMap::new(),
            helper_index: HashMap::new(),
            tls_helper_index: HashMap::new(),
            symbols: vec![],
            dynsym_id,
            dynstr_id,
            hash_id,
            dynsym_size: 0,
            dynstr_size: 0,
            hash_size: 0,
            text_offset: 0,
            data_offset: 0,
            tls_offset: 0,
            plt_offset: 0,
            plt0_idx: None,
            plt_entries: vec![],
            arch,
        };
        // Add NULL symbol
        symtab.add_symbol(
            "",
            Symbol {
                name_idx: 0,
                info: 0,
                other: 0,
                shndx: 0,
                value: 0,
                size: 0,
            },
            SectionKind::Null,
        );
        // Add provided symbols
        symtab.add_symbols(symbols);
        symtab.add_plt_symbols(relocs);
        symtab.add_tls_symbols(relocs);

        // Create .dynstr section
        let dynstr = allocator.get_mut(&dynstr_id);
        dynstr.extend_from_slice(&symtab.dynstr.data);
        symtab.dynstr_size = dynstr.len() as u64;

        // Create .dynsym section
        let dynsym = allocator.get_mut(&dynsym_id);
        for sym in &symtab.dynsym {
            sym.write(dynsym, arch.is_64()).unwrap();
        }
        symtab.dynsym_size = dynsym.len() as u64;

        // Create .hash section
        let hash_section = allocator.get_mut(&hash_id);
        symtab.create_hashtable(hash_section);
        symtab.hash_size = hash_section.len() as u64;

        symtab
    }

    fn add_symbols(&mut self, symbols: &[SymbolDesc]) {
        // Add IFUNC resolver symbol early so it can be used by relocations
        let resolver_name = IFUNC_RESOLVER_NAME;
        let resolver_code = crate::arch::get_ifunc_resolver_code(self.arch);
        let resolver_desc = SymbolDesc::global_func(resolver_name, &resolver_code);
        self.add_single_symbol(resolver_desc);

        for s in symbols {
            self.add_single_symbol(s.clone());
        }
    }

    fn add_single_symbol(&mut self, s: SymbolDesc) -> usize {
        if let Some(idx) = self.sym_index.get(&s.name) {
            return *idx;
        }
        let name = s.name.clone();
        let name_idx = self.dynstr.cur_idx();

        let info = match s.scope {
            SymbolScope::Global => STB_GLOBAL,
            SymbolScope::Local => STB_LOCAL,
            SymbolScope::Weak => STB_WEAK,
        } << 4
            | match s.sym_type {
                SymbolType::Func => STT_FUNC,
                SymbolType::Object => STT_OBJECT,
                SymbolType::Tls => STT_TLS,
            };

        let (shdr_type, value) = if let Some(content) = &s.content {
            let off = match content.kind {
                SectionKind::Text => {
                    let off = self.text_offset;
                    self.text_offset += content.data.len() as u64;
                    off
                }
                SectionKind::Data => {
                    let off = self.data_offset;
                    self.data_offset += content.data.len() as u64;
                    off
                }
                SectionKind::Tls => {
                    let off = self.tls_offset;
                    self.tls_offset += content.data.len() as u64;
                    off
                }
                SectionKind::Plt => {
                    let off = self.plt_offset;
                    self.plt_offset += content.data.len() as u64;
                    off
                }
                _ => todo!("Unsupported purpose in SymbolDesc content"),
            };
            (content.kind, off)
        } else {
            // Undefined symbols
            let shdr_type = match s.sym_type {
                SymbolType::Func => SectionKind::Text,
                SymbolType::Object => SectionKind::Data,
                SymbolType::Tls => SectionKind::Tls,
            };
            (shdr_type, 0)
        };

        let sym = Symbol {
            name_idx,
            info,
            other: 0,
            shndx: 0,
            value,
            size: s
                .size
                .unwrap_or_else(|| s.content.as_ref().map(|c| c.data.len() as u64).unwrap_or(0)),
        };
        let idx = self.add_symbol(&name, sym, shdr_type);
        self.symbols.push(s);
        idx
    }

    pub(crate) fn get_text_content(&self) -> Vec<u8> {
        let mut content = vec![];
        // Sort symbols by value to ensure correct order in section
        let text_syms: Vec<_> = self
            .symbols
            .iter()
            .filter(|s| {
                s.content
                    .as_ref()
                    .map_or(false, |c| matches!(c.kind, SectionKind::Text))
            })
            .collect();

        // We need to find the corresponding Symbol in dynsym to get the value
        // But since we are building the content, we can just use the order they were added
        for s in text_syms {
            if let Some(c) = &s.content {
                content.extend_from_slice(&c.data);
            }
        }
        content
    }

    pub(crate) fn get_plt_content(&self) -> Vec<u8> {
        let mut content = vec![];
        for s in &self.symbols {
            if let Some(c) = &s.content {
                if matches!(c.kind, SectionKind::Plt) {
                    content.extend_from_slice(&c.data);
                }
            }
        }
        content
    }

    pub(crate) fn get_data_content(&self) -> Vec<u8> {
        let mut content = vec![];
        for s in &self.symbols {
            if let Some(c) = &s.content {
                if matches!(c.kind, SectionKind::Data) {
                    content.extend_from_slice(&c.data);
                }
            }
        }
        content
    }

    pub(crate) fn get_tls_content(&self) -> Vec<u8> {
        let mut content = vec![];
        for s in &self.symbols {
            if let Some(c) = &s.content {
                if matches!(c.kind, SectionKind::Tls) {
                    content.extend_from_slice(&c.data);
                }
            }
        }
        content
    }

    pub(crate) fn create_hashtable(&self, hash_table: &mut Vec<u8>) {
        // nbucket
        let nbucket = 1u32;
        hash_table.extend_from_slice(&nbucket.to_le_bytes());
        // nchain
        let nchain = self.dynsym.len() as u32;
        hash_table.extend_from_slice(&nchain.to_le_bytes());
        // buckets
        // bucket[0] points to the first non-null symbol (index 1)
        let first_sym = if self.dynsym.len() > 1 { 1u32 } else { 0u32 };
        hash_table.extend_from_slice(&first_sym.to_le_bytes());

        // chains
        // chain[0] is always 0
        hash_table.extend_from_slice(&0u32.to_le_bytes());
        for i in 1..self.dynsym.len() {
            let next = if i + 1 < self.dynsym.len() {
                (i + 1) as u32
            } else {
                0u32
            };
            hash_table.extend_from_slice(&next.to_le_bytes());
        }
    }

    pub(crate) fn get_sym_idx(&self, name: &str) -> Option<usize> {
        self.sym_index.get(name).cloned()
    }

    pub(crate) fn get_sym_value_by_name(&self, name: &str) -> Option<u64> {
        if let Some(&idx) = self.sym_index.get(name) {
            Some(self.dynsym[idx].value)
        } else {
            None
        }
    }

    pub(crate) fn get_sym_value(&self, idx: usize) -> u64 {
        self.dynsym[idx].value
    }

    pub(crate) fn get_sym_size(&self, idx: usize) -> u64 {
        self.dynsym[idx].size
    }

    pub(crate) fn add_plt_symbols(&mut self, relocs: &[RelocEntry]) {
        let arch = self.arch;
        // Add PLT[0]
        let plt0_code = arch::generate_plt0_code(arch);
        let plt0_desc = SymbolDesc::plt_func("PLT0", plt0_code);
        self.add_single_symbol(plt0_desc);
        self.plt0_idx = Some(self.dynsym.len() - 1);

        let mut got_plt_idx = 3u64; // PLT GOT entries start at index 3 in .got.plt
        let mut reloc_idx = 0u32; // PLT relocation index should be 0-based relative to JMPREL

        for reloc in relocs.iter().filter(|r| r.r_type.is_plt_reloc(arch)) {
            let func_name = reloc.symbol_name.as_str();
            let plt_sym_name = format!("{}@plt", func_name);
            let plt_code = arch::generate_plt_entry_code(arch, reloc_idx, self.plt_offset);
            let plt_desc = SymbolDesc::plt_func(plt_sym_name.clone(), plt_code);
            let plt_idx = self.add_single_symbol(plt_desc);
            self.plt_entries.push((plt_idx, got_plt_idx));

            let test_helper = format!("{}{}", func_name, HELPER_SUFFIX);
            let helper_code = crate::arch::generate_helper_code(self.arch);
            let helper_desc = SymbolDesc::global_func(test_helper, &helper_code);
            let helper_idx = self.add_single_symbol(helper_desc);
            self.helper_index.insert(plt_idx, helper_idx);

            got_plt_idx += 1;
            reloc_idx += 1;
        }
    }

    pub(crate) fn add_tls_symbols(&mut self, relocs: &[RelocEntry]) {
        let arch = self.arch;
        // Add __tls_get_addr as undefined symbol if not present
        if self.get_sym_idx(TLS_GET_ADDR_NAME).is_none() {
            let desc = SymbolDesc::undefined_func(TLS_GET_ADDR_NAME);
            self.add_single_symbol(desc);
        }

        for reloc in relocs.iter().filter(|r| r.r_type.is_tls_reloc(arch)) {
            let tls_name = reloc.symbol_name.as_str();
            if tls_name.is_empty() {
                continue;
            }
            let tls_idx = self.get_sym_idx(tls_name).expect("TLS symbol must exist");

            let test_helper = format!("{}{}", tls_name, TLS_HELPER_SUFFIX);
            if self.get_sym_idx(&test_helper).is_some() {
                continue;
            }

            let helper_code = crate::arch::generate_tls_helper_code(self.arch);
            let helper_desc = SymbolDesc::global_func(test_helper, &helper_code);
            let helper_idx = self.add_single_symbol(helper_desc);
            self.tls_helper_index.insert(tls_idx, helper_idx);
        }
    }

    pub(crate) fn update_symbol_values(
        &mut self,
        plt_vaddr: u64,
        text_vaddr: u64,
        data_vaddr: u64,
        shdr_map: &HashMap<SectionKind, usize>,
    ) {
        for (i, sym) in self.dynsym.iter_mut().enumerate().skip(1) {
            // Skip undefined symbols
            if self.symbols[i - 1].content.is_none() {
                continue;
            }
            let shdr_type = self.dynsym_shdr_types[i];
            if let Some(&sec_idx) = shdr_map.get(&shdr_type) {
                sym.shndx = sec_idx as u16;
                let base_vaddr = match shdr_type {
                    SectionKind::Text => text_vaddr,
                    SectionKind::Data => data_vaddr,
                    SectionKind::Plt => plt_vaddr,
                    SectionKind::Tls => 0, // TLS symbols are relative to TLS segment
                    _ => 0,
                };
                sym.value += base_vaddr;
            }
        }
    }

    pub(crate) fn patch_plt(&self, plt_data: &mut [u8], plt_vaddr: u64, got_plt_vaddr: u64) {
        // 1. Patch PLT0
        if let Some(plt0_idx) = self.plt0_idx {
            let plt0_sym = &self.dynsym[plt0_idx];
            let plt0_off = (plt0_sym.value - plt_vaddr) as usize;
            crate::arch::patch_plt0(self.arch, plt_data, plt0_off, plt0_sym.value, got_plt_vaddr);
        }

        // 2. Patch PLT entries
        let word_size = if self.arch.is_64() { 8 } else { 4 };
        for (plt_idx, got_idx) in &self.plt_entries {
            let plt_sym = &self.dynsym[*plt_idx];
            let plt_off = (plt_sym.value - plt_vaddr) as usize;
            let target_got_vaddr = got_plt_vaddr + (got_idx * word_size);
            crate::arch::patch_plt_entry(
                self.arch,
                plt_data,
                plt_off,
                plt_sym.value,
                target_got_vaddr,
                got_plt_vaddr,
            );
        }
    }

    pub(crate) fn patch_plt_testers(&self, text_data: &mut [u8], text_vaddr: u64, got_vaddr: u64) {
        for (&plt_idx, &helper_idx) in &self.helper_index {
            let plt_sym = &self.dynsym[plt_idx];
            let helper_sym = &self.dynsym[helper_idx];
            let helper_text_off = (helper_sym.value - text_vaddr) as usize;
            let target_plt_vaddr = plt_sym.value;

            crate::arch::patch_plt_testers(
                self.arch,
                text_data,
                helper_text_off,
                helper_sym.value,
                target_plt_vaddr,
                got_vaddr,
            );
        }
    }

    pub(crate) fn patch_tls_testers(
        &self,
        text_data: &mut [u8],
        text_vaddr: u64,
        reloc: &RelocMetaData,
        shdr: &ShdrManager,
        got_vaddr: u64,
    ) {
        let plt_name = format!("{}@plt", TLS_GET_ADDR_NAME);
        let tls_get_addr_vaddr = self
            .get_sym_idx(&plt_name)
            .or_else(|| self.get_sym_idx(TLS_GET_ADDR_NAME))
            .map(|idx| self.dynsym[idx].value)
            .unwrap_or(0);

        for (&tls_idx, &helper_idx) in &self.tls_helper_index {
            let helper_sym = &self.dynsym[helper_idx];
            let helper_text_off = (helper_sym.value - text_vaddr) as usize;

            if let Some(reloc_vaddr) = reloc.find_tls_reloc_vaddr(tls_idx as u64, shdr) {
                crate::arch::patch_tls_tester(
                    self.arch,
                    text_data,
                    helper_text_off,
                    helper_sym.value,
                    reloc_vaddr,
                    tls_get_addr_vaddr,
                    got_vaddr,
                );
            }
        }
    }

    pub(crate) fn patch_ifunc_resolver(
        &self,
        text_data: &mut [u8],
        text_vaddr: u64,
        target_vaddr: u64,
    ) {
        let resolver_name = IFUNC_RESOLVER_NAME;
        if let Some(&resolver_idx) = self.sym_index.get(resolver_name) {
            let resolver_sym = &self.dynsym[resolver_idx];
            let resolver_text_off = (resolver_sym.value - text_vaddr) as usize;
            crate::arch::patch_ifunc_resolver(
                self.arch,
                text_data,
                resolver_text_off,
                resolver_sym.value,
                target_vaddr,
            );
        }
    }

    pub(crate) fn patch_symtab(
        &mut self,
        plt_vaddr: u64,
        text_vaddr: u64,
        data_vaddr: u64,
        shdr_map: &HashMap<SectionKind, usize>,
        allocator: &mut SectionAllocator,
    ) {
        self.update_symbol_values(plt_vaddr, text_vaddr, data_vaddr, shdr_map);
        self.patch_dynsym(allocator);
    }

    pub(crate) fn patch_dynsym(&self, allocator: &mut SectionAllocator) {
        let buf = allocator.get_mut(&self.dynsym_id);
        buf.clear();
        for sym in &self.dynsym {
            sym.write(buf, self.arch.is_64()).unwrap();
        }
    }

    pub(crate) fn create_sections(&mut self, sections: &mut Vec<Section>) {
        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: SectionKind::DynStr,
                addr: 0,
                offset: 0,
                size: self.dynstr_size,
                addralign: 1,
            },
            data: self.dynstr_id,
        });
        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: SectionKind::DynSym,
                addr: 0,
                offset: 0,
                size: self.dynsym_size,
                addralign: 8,
            },
            data: self.dynsym_id,
        });
        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: SectionKind::Hash,
                addr: 0,
                offset: 0,
                size: self.hash_size,
                addralign: 4,
            },
            data: self.hash_id,
        });
    }
}
