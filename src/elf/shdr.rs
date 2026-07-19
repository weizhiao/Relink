//! Section-header related ELF types
//!
//! This module contains section-header views used while scanning ELF sections.

use super::{
    layout::{ElfLayout, NativeElfLayout},
    raw::ElfShdrRaw,
    symbol::ElfSectionIndex,
};
use crate::entity::EntityRef;
use bitflags::bitflags;
use core::fmt::{self, Display};
use elf::abi::*;

/// Semantic wrapper for the ELF `sh_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfSectionType(u32);

impl ElfSectionType {
    /// `SHT_NULL`: inactive section header.
    pub const NULL: Self = Self(SHT_NULL);
    /// `SHT_PROGBITS`: program-defined data.
    pub const PROGBITS: Self = Self(SHT_PROGBITS);
    /// `SHT_SYMTAB`: full symbol table.
    pub const SYMTAB: Self = Self(SHT_SYMTAB);
    /// `SHT_STRTAB`: string table.
    pub const STRTAB: Self = Self(SHT_STRTAB);
    /// `SHT_RELA`: explicit-addend relocation section.
    pub const RELA: Self = Self(SHT_RELA);
    /// `SHT_HASH`: System V symbol hash table.
    pub const HASH: Self = Self(SHT_HASH);
    /// `SHT_DYNAMIC`: dynamic section.
    pub const DYNAMIC: Self = Self(SHT_DYNAMIC);
    /// `SHT_NOTE`: note section.
    pub const NOTE: Self = Self(SHT_NOTE);
    /// `SHT_NOBITS`: allocated data with no file bytes.
    pub const NOBITS: Self = Self(SHT_NOBITS);
    /// `SHT_REL`: implicit-addend relocation section.
    pub const REL: Self = Self(SHT_REL);
    /// `SHT_SHLIB`: reserved section type.
    pub const SHLIB: Self = Self(SHT_SHLIB);
    /// `SHT_DYNSYM`: dynamic symbol table.
    pub const DYNSYM: Self = Self(SHT_DYNSYM);
    /// `SHT_INIT_ARRAY`: initialization function array.
    pub const INIT_ARRAY: Self = Self(SHT_INIT_ARRAY);
    /// `SHT_FINI_ARRAY`: finalization function array.
    pub const FINI_ARRAY: Self = Self(SHT_FINI_ARRAY);
    /// `SHT_PREINIT_ARRAY`: pre-initialization function array.
    pub const PREINIT_ARRAY: Self = Self(SHT_PREINIT_ARRAY);
    /// `SHT_GROUP`: section group.
    pub const GROUP: Self = Self(SHT_GROUP);
    /// `SHT_SYMTAB_SHNDX`: extended symbol section indices.
    pub const SYMTAB_SHNDX: Self = Self(SHT_SYMTAB_SHNDX);

    /// Creates a section type wrapper from a raw `sh_type` value.
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `sh_type` value.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for ElfSectionType {
    #[inline]
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<ElfSectionType> for u32 {
    #[inline]
    fn from(value: ElfSectionType) -> Self {
        value.raw()
    }
}

impl Display for ElfSectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SHT_NULL => f.write_str("SHT_NULL"),
            SHT_PROGBITS => f.write_str("SHT_PROGBITS"),
            SHT_SYMTAB => f.write_str("SHT_SYMTAB"),
            SHT_STRTAB => f.write_str("SHT_STRTAB"),
            SHT_RELA => f.write_str("SHT_RELA"),
            SHT_HASH => f.write_str("SHT_HASH"),
            SHT_DYNAMIC => f.write_str("SHT_DYNAMIC"),
            SHT_NOTE => f.write_str("SHT_NOTE"),
            SHT_NOBITS => f.write_str("SHT_NOBITS"),
            SHT_REL => f.write_str("SHT_REL"),
            SHT_SHLIB => f.write_str("SHT_SHLIB"),
            SHT_DYNSYM => f.write_str("SHT_DYNSYM"),
            SHT_INIT_ARRAY => f.write_str("SHT_INIT_ARRAY"),
            SHT_FINI_ARRAY => f.write_str("SHT_FINI_ARRAY"),
            SHT_PREINIT_ARRAY => f.write_str("SHT_PREINIT_ARRAY"),
            SHT_GROUP => f.write_str("SHT_GROUP"),
            SHT_SYMTAB_SHNDX => f.write_str("SHT_SYMTAB_SHNDX"),
            raw => write!(f, "unknown ELF section type {raw}"),
        }
    }
}

bitflags! {
    /// Bitflags wrapper for the ELF `sh_flags` field.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ElfSectionFlags: u64 {
        /// Section is writable at runtime.
        const WRITE = SHF_WRITE as u64;
        /// Section occupies memory at runtime.
        const ALLOC = SHF_ALLOC as u64;
        /// Section contains executable instructions.
        const EXECINSTR = SHF_EXECINSTR as u64;
        /// Section contains thread-local storage.
        const TLS = SHF_TLS as u64;
    }
}

/// Stable identifier for a real section-header table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ElfSectionId(usize);

impl ElfSectionId {
    /// Creates a section id from a zero-based section-header table index.
    #[inline]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the zero-based section-header table index.
    #[inline]
    pub const fn index(self) -> usize {
        self.0
    }

    /// Converts a symbol `st_shndx` value into a section id when it names a
    /// real section-header table entry.
    #[inline]
    pub const fn from_symbol_shndx(index: ElfSectionIndex) -> Option<Self> {
        if index.is_undef() || index.is_abs() || index.is_common() || index.is_xindex() {
            None
        } else {
            Some(Self::new(index.index()))
        }
    }
}

impl EntityRef for ElfSectionId {
    #[inline]
    fn new(index: usize) -> Self {
        Self(index)
    }

    #[inline]
    fn index(self) -> usize {
        self.0
    }
}

impl Display for ElfSectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ELF section {}", self.0)
    }
}

/// ELF section header describing sections of the ELF file.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfShdr<L: ElfLayout = NativeElfLayout> {
    shdr: L::Shdr,
}

impl<L: ElfLayout> ElfShdr<L> {
    /// Returns the parsed ELF section type of this header.
    #[inline]
    pub fn section_type(&self) -> ElfSectionType {
        ElfSectionType::new(self.shdr.sh_type())
    }

    /// Returns the section name index (`sh_name`) field.
    #[inline]
    pub fn sh_name(&self) -> u32 {
        self.shdr.sh_name()
    }

    /// Returns the parsed ELF section flags of this header.
    #[inline]
    pub fn flags(&self) -> ElfSectionFlags {
        ElfSectionFlags::from_bits_retain(self.shdr.sh_flags())
    }

    /// Returns the section address (`sh_addr`) as a native-sized value.
    #[inline]
    pub fn sh_addr(&self) -> usize {
        self.shdr.sh_addr()
    }

    /// Returns the section file offset (`sh_offset`) as a native-sized value.
    #[inline]
    pub fn sh_offset(&self) -> usize {
        self.shdr.sh_offset()
    }

    /// Returns the section size (`sh_size`) as a native-sized value.
    #[inline]
    pub fn sh_size(&self) -> usize {
        self.shdr.sh_size()
    }

    /// Returns the section link (`sh_link`) field.
    #[inline]
    pub fn sh_link(&self) -> u32 {
        self.shdr.sh_link()
    }

    /// Returns the section info (`sh_info`) field.
    #[inline]
    pub fn sh_info(&self) -> u32 {
        self.shdr.sh_info()
    }

    /// Returns the section alignment (`sh_addralign`) as a native-sized value.
    #[inline]
    pub fn sh_addralign(&self) -> usize {
        self.shdr.sh_addralign()
    }

    /// Returns the section entry size (`sh_entsize`) as a native-sized value.
    #[inline]
    pub fn sh_entsize(&self) -> usize {
        self.shdr.sh_entsize()
    }

    /// Updates the section name index (`sh_name`) field.
    #[inline]
    pub fn set_sh_name(&mut self, name: u32) {
        self.shdr.set_sh_name(name);
    }

    /// Updates the section type (`sh_type`) field.
    #[inline]
    pub fn set_section_type(&mut self, ty: ElfSectionType) {
        self.shdr.set_sh_type(ty.raw());
    }

    /// Updates the section flags (`sh_flags`) field.
    #[inline]
    pub fn set_flags(&mut self, flags: ElfSectionFlags) {
        self.shdr.set_sh_flags(flags.bits());
    }

    /// Updates the section address (`sh_addr`) field.
    #[inline]
    pub fn set_sh_addr(&mut self, addr: usize) {
        self.shdr.set_sh_addr(addr);
    }

    /// Adds an offset to the section address (`sh_addr`) field.
    #[inline]
    pub fn add_sh_addr(&mut self, delta: usize) {
        self.shdr.add_sh_addr(delta);
    }

    /// Updates the section file offset (`sh_offset`) field.
    #[inline]
    pub fn set_sh_offset(&mut self, offset: usize) {
        self.shdr.set_sh_offset(offset);
    }

    /// Updates the section size (`sh_size`) field.
    #[inline]
    pub fn set_sh_size(&mut self, size: usize) {
        self.shdr.set_sh_size(size);
    }

    /// Updates the section link (`sh_link`) field.
    #[inline]
    pub fn set_sh_link(&mut self, link: u32) {
        self.shdr.set_sh_link(link);
    }

    /// Updates the section info (`sh_info`) field.
    #[inline]
    pub fn set_sh_info(&mut self, info: u32) {
        self.shdr.set_sh_info(info);
    }

    /// Updates the section alignment (`sh_addralign`) field.
    #[inline]
    pub fn set_sh_addralign(&mut self, addralign: usize) {
        self.shdr.set_sh_addralign(addralign);
    }

    /// Updates the section entry size (`sh_entsize`) field.
    #[inline]
    pub fn set_sh_entsize(&mut self, entsize: usize) {
        self.shdr.set_sh_entsize(entsize);
    }

    /// Creates a new ELF section header with the specified parameters.
    ///
    /// # Arguments
    /// * `sh_name` - Section name string table index
    /// * `sh_type` - Section type (e.g., PROGBITS, SYMTAB, etc.)
    /// * `sh_flags` - Section flags (e.g., WRITE, ALLOC, EXECINSTR)
    /// * `sh_addr` - Address where section should be loaded
    /// * `sh_offset` - Offset of section in file
    /// * `sh_size` - Size of section in bytes
    /// * `sh_link` - Link to another section (interpretation depends on section type)
    /// * `sh_info` - Extra information (interpretation depends on section type)
    /// * `sh_addralign` - Address alignment constraint
    /// * `sh_entsize` - Size of each entry if section contains a table
    #[cfg(feature = "object")]
    // Mirrors the ELF section-header field list.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sh_name: u32,
        sh_type: ElfSectionType,
        sh_flags: ElfSectionFlags,
        sh_addr: usize,
        sh_offset: usize,
        sh_size: usize,
        sh_link: u32,
        sh_info: u32,
        sh_addralign: usize,
        sh_entsize: usize,
    ) -> Self {
        let mut shdr: L::Shdr = unsafe { core::mem::zeroed() };
        shdr.set_sh_name(sh_name);
        shdr.set_sh_type(sh_type.raw());
        shdr.set_sh_flags(sh_flags.bits());
        shdr.set_sh_addr(sh_addr);
        shdr.set_sh_offset(sh_offset);
        shdr.set_sh_size(sh_size);
        shdr.set_sh_link(sh_link);
        shdr.set_sh_info(sh_info);
        shdr.set_sh_addralign(sh_addralign);
        shdr.set_sh_entsize(sh_entsize);
        Self { shdr }
    }
}
