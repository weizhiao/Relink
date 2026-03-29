//! Section-header related ELF types
//!
//! This module contains the semantic wrapper types for ELF section headers,
//! including `ElfSectionType`, `ElfSectionFlags`, and `ElfShdr`.

use bitflags::bitflags;
use core::fmt::{self, Display};
use elf::abi::{
    SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_DYNAMIC, SHT_DYNSYM, SHT_FINI_ARRAY, SHT_GROUP,
    SHT_HASH, SHT_INIT_ARRAY, SHT_NOBITS, SHT_NOTE, SHT_NULL, SHT_PREINIT_ARRAY, SHT_PROGBITS,
    SHT_REL, SHT_RELA, SHT_SHLIB, SHT_STRTAB, SHT_SYMTAB, SHT_SYMTAB_SHNDX,
};

use super::defs::{ElfLayout, NativeElfLayout};

/// Semantic wrapper for the ELF `sh_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfSectionType(u32);

impl ElfSectionType {
    pub const NULL: Self = Self(SHT_NULL);
    pub const PROGBITS: Self = Self(SHT_PROGBITS);
    pub const SYMTAB: Self = Self(SHT_SYMTAB);
    pub const STRTAB: Self = Self(SHT_STRTAB);
    pub const RELA: Self = Self(SHT_RELA);
    pub const HASH: Self = Self(SHT_HASH);
    pub const DYNAMIC: Self = Self(SHT_DYNAMIC);
    pub const NOTE: Self = Self(SHT_NOTE);
    pub const NOBITS: Self = Self(SHT_NOBITS);
    pub const REL: Self = Self(SHT_REL);
    pub const SHLIB: Self = Self(SHT_SHLIB);
    pub const DYNSYM: Self = Self(SHT_DYNSYM);
    pub const INIT_ARRAY: Self = Self(SHT_INIT_ARRAY);
    pub const FINI_ARRAY: Self = Self(SHT_FINI_ARRAY);
    pub const PREINIT_ARRAY: Self = Self(SHT_PREINIT_ARRAY);
    pub const GROUP: Self = Self(SHT_GROUP);
    pub const SYMTAB_SHNDX: Self = Self(SHT_SYMTAB_SHNDX);

    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

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
        const WRITE = SHF_WRITE as u64;
        const ALLOC = SHF_ALLOC as u64;
        const EXECINSTR = SHF_EXECINSTR as u64;
    }
}

/// ELF section header describing sections of the ELF file.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfShdr {
    shdr: <NativeElfLayout as ElfLayout>::Shdr,
}

impl ElfShdr {
    /// Returns the parsed ELF section type of this header.
    #[inline]
    pub const fn section_type(&self) -> ElfSectionType {
        ElfSectionType::new(self.shdr.sh_type)
    }

    /// Returns the section name index (`sh_name`) field.
    #[inline]
    pub const fn sh_name(&self) -> u32 {
        self.shdr.sh_name
    }

    /// Returns the parsed ELF section flags of this header.
    #[inline]
    pub fn flags(&self) -> ElfSectionFlags {
        ElfSectionFlags::from_bits_retain(self.shdr.sh_flags as u64)
    }

    /// Returns the section address (`sh_addr`) as a native-sized value.
    #[inline]
    pub fn sh_addr(&self) -> usize {
        self.shdr.sh_addr as usize
    }

    /// Returns the section file offset (`sh_offset`) as a native-sized value.
    #[inline]
    pub fn sh_offset(&self) -> usize {
        self.shdr.sh_offset as usize
    }

    /// Returns the section size (`sh_size`) as a native-sized value.
    #[inline]
    pub fn sh_size(&self) -> usize {
        self.shdr.sh_size as usize
    }

    /// Returns the section link (`sh_link`) field.
    #[inline]
    pub const fn sh_link(&self) -> u32 {
        self.shdr.sh_link
    }

    /// Returns the section info (`sh_info`) field.
    #[inline]
    pub const fn sh_info(&self) -> u32 {
        self.shdr.sh_info
    }

    /// Returns the section alignment (`sh_addralign`) as a native-sized value.
    #[inline]
    pub fn sh_addralign(&self) -> usize {
        self.shdr.sh_addralign as usize
    }

    /// Returns the section entry size (`sh_entsize`) as a native-sized value.
    #[inline]
    pub fn sh_entsize(&self) -> usize {
        self.shdr.sh_entsize as usize
    }

    /// Updates the section address (`sh_addr`) field.
    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn set_sh_addr(&mut self, addr: usize) {
        self.shdr.sh_addr = addr as _;
    }

    /// Adds an offset to the section address (`sh_addr`) field.
    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn add_sh_addr(&mut self, delta: usize) {
        self.shdr.sh_addr = self.shdr.sh_addr.wrapping_add(delta as _);
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
        let mut shdr: <NativeElfLayout as ElfLayout>::Shdr = unsafe { core::mem::zeroed() };
        shdr.sh_name = sh_name;
        shdr.sh_type = sh_type.raw();
        shdr.sh_flags = sh_flags.bits() as _;
        shdr.sh_addr = sh_addr as _;
        shdr.sh_offset = sh_offset as _;
        shdr.sh_size = sh_size as _;
        shdr.sh_link = sh_link;
        shdr.sh_info = sh_info;
        shdr.sh_addralign = sh_addralign as _;
        shdr.sh_entsize = sh_entsize as _;
        Self { shdr }
    }
}

impl ElfShdr {
    /// Returns a reference to the section content as a slice of the specified type.
    ///
    /// This method provides safe access to section data by interpreting the section
    /// as a contiguous array of elements of type `T`. The section must contain a table
    /// of fixed-size entries for this to be meaningful.
    ///
    /// # Safety
    /// The caller must ensure that the section actually contains valid data of type `T`
    /// and that the alignment and size constraints are met.
    ///
    /// # Panics
    /// Panics in debug builds if the element size doesn't match the section's entry size,
    /// if the section size is not divisible by the entry size, or if the address is not
    /// properly aligned.
    #[cfg(feature = "object")]
    pub(crate) fn content<T>(&self) -> &'static [T] {
        self.content_mut()
    }

    /// Returns a mutable reference to the section content as a slice of the specified type.
    ///
    /// This method provides mutable access to section data. Use with caution as it allows
    /// modification of the underlying ELF data.
    ///
    /// # Safety
    /// The caller must ensure that the section actually contains valid data of type `T`
    /// and that the alignment and size constraints are met. Modifying section data may
    /// corrupt the ELF file or cause runtime errors.
    ///
    /// # Panics
    /// Panics in debug builds if the element size doesn't match the section's entry size,
    /// if the section size is not divisible by the entry size, or if the address is not
    /// properly aligned.
    #[cfg(feature = "object")]
    pub(crate) fn content_mut<T>(&self) -> &'static mut [T] {
        let start = self.sh_addr();
        let len = self.sh_size() / self.sh_entsize();
        debug_assert!(core::mem::size_of::<T>() == self.sh_entsize());
        debug_assert!(self.sh_size().is_multiple_of(self.sh_entsize()));
        debug_assert!(self.sh_addr().is_multiple_of(self.sh_addralign()));
        unsafe { core::slice::from_raw_parts_mut(start as *mut T, len) }
    }
}
