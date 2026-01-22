use crate::Arch;
use crate::common::{RelocEntry, SectionKind, SymbolDesc};
use crate::dylib::data::DataMetaData;
use crate::dylib::dynamic::DynamicMetadata;
use crate::dylib::layout::ElfLayout;
use crate::dylib::reloc::RelocMetaData;
use crate::dylib::shdr::{SectionAllocator, ShdrManager};
use crate::dylib::symtab::SymTabMetadata;
use crate::dylib::text::CodeMetaData;
use crate::dylib::tls::TlsMetaData;
use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};
use object::elf::*;
use std::path::Path;

mod data;
mod dynamic;
mod layout;
pub(crate) mod reloc;
pub(crate) mod shdr;
pub(crate) mod symtab;
pub(crate) mod text;
mod tls;

fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) / align * align
}

pub(crate) struct StringTable {
    data: Vec<u8>,
}

impl StringTable {
    pub(crate) fn new() -> Self {
        Self { data: vec![0u8] } // initial null byte
    }

    pub(crate) fn add(&mut self, s: &str) -> u32 {
        let idx = self.data.len() as u32;
        self.data.extend_from_slice(s.as_bytes());
        self.data.push(0);
        idx
    }

    pub(crate) fn cur_idx(&self) -> u32 {
        self.data.len() as u32
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Clone)]
pub struct ElfWriterConfig {
    /// Base address for memory mapping (default: 0x400000)
    pub base_addr: u64,
    /// Page size for alignment (default: 0x1000)
    pub page_size: u64,
    /// Custom value for IFUNC resolver to return (default: None, returns PLT0 address)
    pub ifunc_resolver_val: Option<u64>,
}

impl Default for ElfWriterConfig {
    fn default() -> Self {
        Self {
            base_addr: 0,
            page_size: 0x1000,
            ifunc_resolver_val: None,
        }
    }
}

impl ElfWriterConfig {
    /// Create a default configuration
    pub fn default() -> Self {
        <Self as Default>::default()
    }

    /// Set custom base address
    pub fn with_base_addr(mut self, addr: u64) -> Self {
        self.base_addr = addr;
        self
    }

    /// Set custom page size
    pub fn with_page_size(mut self, size: u64) -> Self {
        self.page_size = size;
        self
    }

    /// Set custom IFUNC resolver return value
    pub fn with_ifunc_resolver_val(mut self, val: u64) -> Self {
        self.ifunc_resolver_val = Some(val);
        self
    }
}

/// Relocation metadata for testing and verification
/// Relocation metadata for testing and verification.
#[derive(Clone, Debug)]
pub struct RelocationInfo {
    /// Virtual address where the relocation is applied.
    pub vaddr: u64,
    /// Architecture-specific relocation type.
    pub r_type: u32,
    /// Index of the symbol in the dynamic symbol table.
    pub sym_idx: u64,
    /// Addend for the relocation.
    pub addend: i64,
    /// Size of the referenced symbol (useful for COPY relocations).
    pub sym_size: u64,
}

/// Result of an ELF generation process.
#[derive(Clone)]
pub struct ElfWriteOutput {
    /// Raw bytes of the generated ELF file.
    pub data: Vec<u8>,
    /// Base address used for virtual address calculations.
    pub base_addr: u64,
    /// Virtual address of the data segment.
    pub data_vaddr: u64,
    /// Virtual address of the text segment.
    pub text_vaddr: u64,
    /// List of dynamic relocations generated.
    pub relocations: Vec<RelocationInfo>,
    /// The value returned by the IFUNC resolver.
    pub ifunc_resolver_val: u64,
}

// Constants to replace magic numbers
const EHDR_SIZE_64: u64 = 64;
const EHDR_SIZE_32: u64 = 52;
const PHDR_SIZE_64: u64 = 56;
const PHDR_SIZE_32: u64 = 32;
const SHDR_SIZE_64: u64 = 64;
const SHDR_SIZE_32: u64 = 40;
const SYM_SIZE_64: u64 = 24;
const SYM_SIZE_32: u64 = 16;
const RELA_SIZE_64: u64 = 24;
const RELA_SIZE_32: u64 = 12;
const REL_SIZE_64: u64 = 16;
const REL_SIZE_32: u64 = 8;
const DYN_SIZE_64: u64 = 16;
const DYN_SIZE_32: u64 = 8;
const HASH_SIZE: u64 = 4;

/// A writer for generating dynamic library (Shared Object) ELF files.
pub struct DylibWriter {
    arch: Arch,
    config: ElfWriterConfig,
}

impl DylibWriter {
    /// Create a new DylibWriter for the specified architecture with default configuration.
    pub fn new(arch: Arch) -> Self {
        let config = ElfWriterConfig::default();
        Self { arch, config }
    }

    /// Create a new DylibWriter with a custom configuration.
    pub fn with_config(arch: Arch, config: ElfWriterConfig) -> Self {
        Self { arch, config }
    }

    /// Write the generated ELF to a file and return the metadata.
    pub fn write_file(
        &self,
        out_path: &Path,
        relocs: &[RelocEntry],
        symbols: &[SymbolDesc],
    ) -> Result<ElfWriteOutput> {
        let output = self.write(relocs, symbols)?;
        std::fs::write(out_path, &output.data)?;
        Ok(output)
    }

    /// Generate the ELF bytes and metadata.
    pub fn write(
        &self,
        raw_relocs: &[RelocEntry],
        symbols: &[SymbolDesc],
    ) -> Result<ElfWriteOutput> {
        let is_64 = self.arch.is_64();

        // Preprocess relocations
        let final_relocs = RelocMetaData::preprocess(self.arch, raw_relocs);

        let mut allocator = SectionAllocator::new();
        let mut symtab = SymTabMetadata::new(self.arch, symbols, &final_relocs, &mut allocator);
        let mut reloc = RelocMetaData::new(self.arch, &final_relocs, &symtab, &mut allocator)?;

        let data = DataMetaData::new(&reloc, &symtab, &mut allocator);
        let mut text = CodeMetaData::new(&symtab, &mut allocator);
        let tls = TlsMetaData::new(&symtab, &mut allocator);

        // 1. Create initial sections
        let mut sections = vec![];
        text.create_sections(&mut sections);
        data.create_sections(&mut sections);
        tls.create_section(&mut sections);
        symtab.create_sections(&mut sections);
        reloc.create_sections(&mut sections)?;

        // 2. Create .dynamic section (placeholder)
        let mut dyn_meta = DynamicMetadata::new(self.arch, &sections, &mut allocator);
        dyn_meta.create_section(&mut sections);

        // 3. Initialize ShdrManager and Layout
        let mut shdr_manager = ShdrManager::new();
        for sec in sections {
            shdr_manager.add_section(sec.header, sec.data);
        }

        // 4. Build .shstrtab
        shdr_manager.create_shstrtab_section(&mut allocator);

        // 5. Layout
        let mut layout = ElfLayout::new(&self.config);
        let ehdr_size = if is_64 { EHDR_SIZE_64 } else { EHDR_SIZE_32 };
        let ph_size =
            (if is_64 { PHDR_SIZE_64 } else { PHDR_SIZE_32 }) * shdr_manager.get_phnum() as u64;
        layout.add_header(ehdr_size, ph_size);
        shdr_manager.layout(&mut layout);

        // 6. Update all metadata with final addresses
        let shdr_map = shdr_manager.get_shdr_map();
        let plt_vaddr = shdr_manager.get_vaddr(SectionKind::Plt);
        let text_vaddr = shdr_manager.get_vaddr(SectionKind::Text);
        let data_vaddr = shdr_manager.get_vaddr(SectionKind::Data);
        let got_plt_vaddr = shdr_manager.get_vaddr(SectionKind::GotPlt);

        // Update symbols
        symtab.patch_symtab(plt_vaddr, text_vaddr, data_vaddr, &shdr_map, &mut allocator);

        // Update PLT and Text
        let resolver_val = self.config.ifunc_resolver_val.unwrap_or(plt_vaddr);
        text.patch_text(
            plt_vaddr,
            text_vaddr,
            got_plt_vaddr,
            resolver_val,
            &symtab,
            &reloc,
            &shdr_manager,
            &mut allocator,
        );

        // Update GOT and Relocations
        reloc.patch_all(&shdr_manager, &symtab, &mut allocator)?;

        // Update Dynamic
        dyn_meta.patch_dynamic(&shdr_manager, &reloc, &mut allocator, got_plt_vaddr)?;

        // 7. Write final ELF
        let mut out_bytes = vec![];
        // Write EHDR
        let ehdr = ElfHeader {
            ident: self.get_ident(),
            type_: ET_DYN,
            machine: self.get_machine(),
            version: EV_CURRENT as u32,
            entry: 0,
            phoff: ehdr_size,
            shoff: layout.file_off,
            flags: self.get_flags(),
            ehsize: ehdr_size as u16,
            phentsize: (if is_64 { PHDR_SIZE_64 } else { PHDR_SIZE_32 }) as u16,
            phnum: shdr_manager.get_phnum(),
            shentsize: (if is_64 { SHDR_SIZE_64 } else { SHDR_SIZE_32 }) as u16,
            shnum: (shdr_manager.get_shdr_count() + 1) as u16,
            shstrndx: *shdr_map.get(&SectionKind::ShStrTab).unwrap() as u16,
        };
        ehdr.write(&mut out_bytes, is_64)?;

        // Write PHDRs
        shdr_manager.write_phdrs(&mut out_bytes, is_64, self.config.page_size)?;

        // Write Sections
        for sec in shdr_manager.get_sections() {
            self.write_at(&mut out_bytes, sec.header.offset, allocator.get(&sec.data));
        }

        // Write SHDRs
        let mut shdr_buf = vec![];
        shdr_manager.write_shdrs(&mut shdr_buf, is_64)?;
        self.write_at(&mut out_bytes, layout.file_off, &shdr_buf);

        Ok(ElfWriteOutput {
            data: out_bytes,
            base_addr: self.config.base_addr,
            data_vaddr,
            text_vaddr,
            relocations: reloc.get_relocation_infos(),
            ifunc_resolver_val: resolver_val,
        })
    }

    fn get_ident(&self) -> [u8; 16] {
        let mut ident = [0u8; 16];
        ident[0] = 0x7f;
        ident[1] = b'E';
        ident[2] = b'L';
        ident[3] = b'F';
        ident[4] = if self.arch.is_64() { 2 } else { 1 };
        ident[5] = 1; // Little endian
        ident[6] = 1; // Version
        ident[7] = 0; // OS ABI
        ident
    }

    fn write_at(&self, buf: &mut Vec<u8>, offset: u64, data: &[u8]) {
        let offset = offset as usize;
        if buf.len() < offset + data.len() {
            buf.resize(offset + data.len(), 0);
        }
        buf[offset..offset + data.len()].copy_from_slice(data);
    }

    fn get_flags(&self) -> u32 {
        match self.arch {
            Arch::Riscv64 | Arch::Riscv32 => {
                // EF_RISCV_RVC | EF_RISCV_FLOAT_ABI_DOUBLE
                0x0001 | 0x0004
            }
            Arch::Arm => {
                // EF_ARM_EABI_VER5 | EF_ARM_ABI_FLOAT_HARD
                0x05000000 | 0x00000400
            }
            _ => 0,
        }
    }

    fn get_machine(&self) -> u16 {
        match self.arch {
            Arch::X86_64 => EM_X86_64,
            Arch::X86 => EM_386,
            Arch::Aarch64 => EM_AARCH64,
            Arch::Riscv64 => EM_RISCV,
            Arch::Riscv32 => EM_RISCV,
            Arch::Arm => EM_ARM,
            Arch::Loongarch64 => EM_LOONGARCH,
        }
    }
}

struct ElfHeader {
    ident: [u8; 16],
    type_: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

impl ElfHeader {
    fn write(&self, buf: &mut Vec<u8>, is_64: bool) -> Result<()> {
        buf.extend_from_slice(&self.ident);
        buf.write_u16::<LittleEndian>(self.type_)?;
        buf.write_u16::<LittleEndian>(self.machine)?;
        buf.write_u32::<LittleEndian>(self.version)?;
        if is_64 {
            buf.write_u64::<LittleEndian>(self.entry)?;
            buf.write_u64::<LittleEndian>(self.phoff)?;
            buf.write_u64::<LittleEndian>(self.shoff)?;
        } else {
            buf.write_u32::<LittleEndian>(self.entry as u32)?;
            buf.write_u32::<LittleEndian>(self.phoff as u32)?;
            buf.write_u32::<LittleEndian>(self.shoff as u32)?;
        }
        buf.write_u32::<LittleEndian>(self.flags)?;
        buf.write_u16::<LittleEndian>(self.ehsize)?;
        buf.write_u16::<LittleEndian>(self.phentsize)?;
        buf.write_u16::<LittleEndian>(self.phnum)?;
        buf.write_u16::<LittleEndian>(self.shentsize)?;
        buf.write_u16::<LittleEndian>(self.shnum)?;
        buf.write_u16::<LittleEndian>(self.shstrndx)?;
        Ok(())
    }
}
