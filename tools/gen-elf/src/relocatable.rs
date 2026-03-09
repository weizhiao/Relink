use crate::Arch;
use crate::common::{
    RelocEntry, SectionKind, SymbolDesc, SymbolScope as CommonSymbolScope, SymbolType,
};
use anyhow::Result;
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind as ObjectSectionKind, SymbolKind,
    SymbolScope,
    write::{Object, Relocation, Symbol, SymbolSection},
};
use std::collections::HashMap;

/// Result of a relocatable object file generation.
pub struct ObjectElfOutput {
    /// Raw bytes of the generated ELF file.
    pub data: Vec<u8>,
    /// Offsets where relocations were applied.
    pub reloc_offsets: Vec<u64>,
}

/// A writer for generating relocatable object (.o) ELF files.
pub struct ObjectWriter {
    arch: Arch,
}

impl ObjectWriter {
    /// Create a new ObjectWriter for the specified architecture.
    pub fn new(arch: Arch) -> Self {
        Self { arch }
    }

    /// Generate the relocatable ELF bytes and metadata.
    pub fn write(&self, symbols: &[SymbolDesc], relocs: &[RelocEntry]) -> Result<ObjectElfOutput> {
        gen_static_elf(self.arch, symbols, relocs)
    }

    /// Write the generated relocatable ELF to a file and return the metadata.
    pub fn write_file(
        &self,
        out_path: &std::path::Path,
        symbols: &[SymbolDesc],
        relocs: &[RelocEntry],
    ) -> Result<ObjectElfOutput> {
        let output = self.write(symbols, relocs)?;
        std::fs::write(out_path, &output.data)?;
        Ok(output)
    }
}

fn gen_static_elf(
    arch: Arch,
    symbols: &[SymbolDesc],
    relocs: &[RelocEntry],
) -> Result<ObjectElfOutput> {
    let obj_arch: Architecture = arch.into();
    let mut obj = Object::new(BinaryFormat::Elf, obj_arch, Endianness::Little);

    let mut section_map = HashMap::new();
    let mut symbol_map = HashMap::new();
    let mut reloc_offsets = Vec::new();

    // First pass: create sections and add defined symbols
    for sym_desc in symbols {
        if let Some(content) = &sym_desc.content {
            let section_id = *section_map.entry(content.kind).or_insert_with(|| {
                let (name, kind) = match content.kind {
                    SectionKind::Text => (".text", ObjectSectionKind::Text),
                    SectionKind::Data => (".data", ObjectSectionKind::Data),
                    SectionKind::Plt => (".plt", ObjectSectionKind::Text),
                    SectionKind::Tls => (".tdata", ObjectSectionKind::Tls),
                    _ => (".data", ObjectSectionKind::Data),
                };
                obj.add_section(vec![], name.as_bytes().to_vec(), kind)
            });

            let offset = obj.append_section_data(section_id, &content.data, 8);

            let symbol_id = obj.add_symbol(Symbol {
                name: sym_desc.name.as_bytes().to_vec(),
                value: offset,
                size: content.data.len() as u64,
                kind: match sym_desc.sym_type {
                    SymbolType::Func => SymbolKind::Text,
                    SymbolType::Object => SymbolKind::Data,
                    SymbolType::Tls => SymbolKind::Tls,
                },
                scope: match sym_desc.scope {
                    CommonSymbolScope::Global => SymbolScope::Dynamic,
                    CommonSymbolScope::Local => SymbolScope::Compilation,
                    CommonSymbolScope::Weak => SymbolScope::Dynamic,
                },
                weak: sym_desc.scope == CommonSymbolScope::Weak,
                section: SymbolSection::Section(section_id),
                flags: object::SymbolFlags::None,
            });
            symbol_map.insert(sym_desc.name.clone(), symbol_id);
        }
    }

    // Second pass: add undefined symbols
    for sym_desc in symbols {
        if sym_desc.content.is_none() {
            let symbol_id = obj.add_symbol(Symbol {
                name: sym_desc.name.as_bytes().to_vec(),
                value: 0,
                size: 0,
                kind: match sym_desc.sym_type {
                    SymbolType::Func => SymbolKind::Text,
                    SymbolType::Object => SymbolKind::Data,
                    SymbolType::Tls => SymbolKind::Tls,
                },
                scope: SymbolScope::Dynamic,
                weak: sym_desc.scope == CommonSymbolScope::Weak,
                section: SymbolSection::Undefined,
                flags: object::SymbolFlags::None,
            });
            symbol_map.insert(sym_desc.name.clone(), symbol_id);
        }
    }

    // Add relocations
    // For relocatable objects, we usually put relocations in the section they apply to.
    // Here we assume all relocations apply to the first section that has data, or we need more info.
    // In the dylib case, relocations are more global.
    // Let's assume for now they apply to the .text section if it exists, or .data.

    let target_section_id = section_map
        .get(&SectionKind::Text)
        .or_else(|| section_map.get(&SectionKind::Data))
        .copied();

    if let Some(section_id) = target_section_id {
        let word_size = if arch.is_64() { 8 } else { 4 };
        for (idx, reloc) in relocs.iter().enumerate() {
            let symbol_id = if reloc.symbol_name.is_empty() {
                // Section-relative relocation
                obj.section_symbol(section_id)
            } else {
                *symbol_map.get(&reloc.symbol_name).ok_or_else(|| {
                    anyhow::anyhow!("Symbol not found for relocation: {}", reloc.symbol_name)
                })?
            };

            // Auto-calculate offset based on relocation sequence
            // Each relocation is word_size bytes apart starting from offset 0x10
            let offset = 0x10 + (idx as u64 * word_size);
            reloc_offsets.push(offset);

            let flags = object::write::RelocationFlags::Elf {
                r_type: reloc.r_type.0,
            };

            obj.add_relocation(
                section_id,
                Relocation {
                    offset,
                    symbol: symbol_id,
                    addend: reloc.addend,
                    flags,
                },
            )?;
        }
    }

    // Write object file bytes
    let elf_data = obj.write()?;

    Ok(ObjectElfOutput {
        data: elf_data,
        reloc_offsets,
    })
}
