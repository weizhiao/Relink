//! ELF format definitions and utilities.
//!
//! This module provides core ELF (Executable and Linkable Format) data structures
//! and helper functions for parsing and manipulating ELF files. It includes
//! definitions for relocation entries, symbols, program headers, and section headers,
//! with support for both 32-bit and 64-bit ELF formats.

use bitflags::bitflags;
use core::fmt::{self, Display};
use elf::abi::{
    ELFCLASS32, ELFCLASS64, ELFCLASSNONE, EM_386, EM_AARCH64, EM_ARM, EM_RISCV,
    EM_X86_64, ET_CORE, ET_DYN, ET_EXEC, ET_NONE, ET_REL, PF_R, PF_W, PF_X, PT_DYNAMIC,
    PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_INTERP, PT_LOAD, PT_NOTE, PT_NULL, PT_PHDR, PT_SHLIB, PT_TLS,
    SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_DYNAMIC, SHT_DYNSYM, SHT_FINI_ARRAY, SHT_GROUP,
    SHT_HASH, SHT_INIT_ARRAY, SHT_NOBITS, SHT_NOTE, SHT_NULL, SHT_PREINIT_ARRAY, SHT_PROGBITS,
    SHT_REL, SHT_RELA, SHT_SHLIB, SHT_STRTAB, SHT_SYMTAB, SHT_SYMTAB_SHNDX,
};

use crate::arch::rel_type_to_str;

#[cfg(not(target_pointer_width = "64"))]
pub(crate) use super::symbol::Elf32Sym;

/// Groups the raw ELF types/constants selected for the current target.
///
/// Keeping this behind a single trait lets us centralize the pointer-width
/// mapping without forcing the rest of the module to become generic.
#[doc(hidden)]
pub(crate) trait ElfLayout {
    const E_CLASS: u8;
    const REL_MASK: usize;
    const REL_BIT: usize;

    type Phdr;
    type Shdr;
    type Dyn;
    type Ehdr;
    type Rela;
    type Rel;
    type Relr;
    type Sym;
}

#[doc(hidden)]
pub struct NativeElfLayout;

#[cfg(target_pointer_width = "64")]
impl ElfLayout for NativeElfLayout {
    const E_CLASS: u8 = elf::abi::ELFCLASS64;
    const REL_MASK: usize = 0xFFFFFFFF;
    const REL_BIT: usize = 32;

    type Phdr = elf::segment::Elf64_Phdr;
    type Shdr = elf::section::Elf64_Shdr;
    type Dyn = elf::dynamic::Elf64_Dyn;
    type Ehdr = elf::file::Elf64_Ehdr;
    type Rela = elf::relocation::Elf64_Rela;
    type Rel = elf::relocation::Elf64_Rel;
    type Relr = u64;
    type Sym = elf::symbol::Elf64_Sym;
}

#[cfg(not(target_pointer_width = "64"))]
impl ElfLayout for NativeElfLayout {
    const E_CLASS: u8 = elf::abi::ELFCLASS32;
    const REL_MASK: usize = 0xFF;
    const REL_BIT: usize = 8;

    type Phdr = elf::segment::Elf32_Phdr;
    type Shdr = elf::section::Elf32_Shdr;
    type Dyn = elf::dynamic::Elf32_Dyn;
    type Ehdr = elf::file::Elf32_Ehdr;
    type Rela = elf::relocation::Elf32_Rela;
    type Rel = elf::relocation::Elf32_Rel;
    type Relr = u32;
    type Sym = Elf32Sym;
}

pub(crate) const E_CLASS: u8 = <NativeElfLayout as ElfLayout>::E_CLASS;
pub(crate) const REL_MASK: usize = <NativeElfLayout as ElfLayout>::REL_MASK;
pub(crate) const REL_BIT: usize = <NativeElfLayout as ElfLayout>::REL_BIT;

pub(crate) type ElfEhdr = <NativeElfLayout as ElfLayout>::Ehdr;
pub(crate) const EHDR_SIZE: usize = core::mem::size_of::<ElfEhdr>();

/// Semantic wrapper for the ELF `EI_CLASS` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfClass(u8);

impl ElfClass {
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }
}

impl From<u8> for ElfClass {
    #[inline]
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<ElfClass> for u8 {
    #[inline]
    fn from(value: ElfClass) -> Self {
        value.raw()
    }
}

impl Display for ElfClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ELFCLASSNONE => f.write_str("ELFCLASSNONE"),
            ELFCLASS32 => f.write_str("ELF32"),
            ELFCLASS64 => f.write_str("ELF64"),
            raw => write!(f, "unknown ELF class {raw}"),
        }
    }
}

/// Semantic wrapper for the ELF `e_machine` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfMachine(u16);

impl ElfMachine {
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl From<u16> for ElfMachine {
    #[inline]
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<ElfMachine> for u16 {
    #[inline]
    fn from(value: ElfMachine) -> Self {
        value.raw()
    }
}

impl Display for ElfMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            EM_X86_64 => f.write_str("x86_64"),
            EM_AARCH64 => f.write_str("AArch64"),
            EM_RISCV => f.write_str("RISC-V"),
            EM_386 => f.write_str("x86"),
            EM_ARM => f.write_str("ARM"),
            258 => f.write_str("LoongArch"),
            raw => write!(f, "unknown ELF machine {raw}"),
        }
    }
}

/// Semantic wrapper for the ELF `e_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfFileType(u16);

impl ElfFileType {
    pub const NONE: Self = Self(ET_NONE);
    pub const REL: Self = Self(ET_REL);
    pub const EXEC: Self = Self(ET_EXEC);
    pub const DYN: Self = Self(ET_DYN);
    pub const CORE: Self = Self(ET_CORE);

    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl From<u16> for ElfFileType {
    #[inline]
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<ElfFileType> for u16 {
    #[inline]
    fn from(value: ElfFileType) -> Self {
        value.raw()
    }
}

impl Display for ElfFileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ET_NONE => f.write_str("ET_NONE"),
            ET_REL => f.write_str("ET_REL"),
            ET_EXEC => f.write_str("ET_EXEC"),
            ET_DYN => f.write_str("ET_DYN"),
            ET_CORE => f.write_str("ET_CORE"),
            raw => write!(f, "unknown ELF file type {raw}"),
        }
    }
}

/// Semantic wrapper for the ELF `p_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfProgramType(u32);

impl ElfProgramType {
    pub const NULL: Self = Self(PT_NULL);
    pub const LOAD: Self = Self(PT_LOAD);
    pub const DYNAMIC: Self = Self(PT_DYNAMIC);
    pub const INTERP: Self = Self(PT_INTERP);
    pub const NOTE: Self = Self(PT_NOTE);
    pub const SHLIB: Self = Self(PT_SHLIB);
    pub const PHDR: Self = Self(PT_PHDR);
    pub const TLS: Self = Self(PT_TLS);
    pub const GNU_EH_FRAME: Self = Self(PT_GNU_EH_FRAME);
    pub const GNU_RELRO: Self = Self(PT_GNU_RELRO);

    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for ElfProgramType {
    #[inline]
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<ElfProgramType> for u32 {
    #[inline]
    fn from(value: ElfProgramType) -> Self {
        value.raw()
    }
}

impl Display for ElfProgramType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            PT_NULL => f.write_str("PT_NULL"),
            PT_LOAD => f.write_str("PT_LOAD"),
            PT_DYNAMIC => f.write_str("PT_DYNAMIC"),
            PT_INTERP => f.write_str("PT_INTERP"),
            PT_NOTE => f.write_str("PT_NOTE"),
            PT_SHLIB => f.write_str("PT_SHLIB"),
            PT_PHDR => f.write_str("PT_PHDR"),
            PT_TLS => f.write_str("PT_TLS"),
            PT_GNU_EH_FRAME => f.write_str("PT_GNU_EH_FRAME"),
            PT_GNU_RELRO => f.write_str("PT_GNU_RELRO"),
            raw => write!(f, "unknown ELF program type {raw}"),
        }
    }
}

bitflags! {
    /// Bitflags wrapper for the ELF `p_flags` field.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ElfProgramFlags: u32 {
        const EXEC = PF_X;
        const WRITE = PF_W;
        const READ = PF_R;
    }
}

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

/// ELF RELR relocation entry.
#[repr(transparent)]
pub struct ElfRelr {
    relr: <NativeElfLayout as ElfLayout>::Relr,
}

impl ElfRelr {
    /// Returns the value of the relocation entry.
    #[inline]
    pub fn value(&self) -> usize {
        self.relr as usize
    }
}

/// ELF RELA relocation entry.
#[repr(transparent)]
pub struct ElfRela {
    rela: <NativeElfLayout as ElfLayout>::Rela,
}

impl ElfRela {
    /// Returns the relocation type.
    #[inline]
    pub fn r_type(&self) -> usize {
        self.rela.r_info as usize & REL_MASK
    }

    /// Returns the symbol index.
    #[inline]
    pub fn r_symbol(&self) -> usize {
        self.rela.r_info as usize >> REL_BIT
    }

    /// Returns the relocation offset.
    #[inline]
    pub fn r_offset(&self) -> usize {
        self.rela.r_offset as usize
    }

    /// Returns the relocation addend.
    #[inline]
    pub fn r_addend(&self, _base: usize) -> isize {
        self.rela.r_addend as isize
    }

    /// Sets the relocation offset.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rela.r_offset = offset as _;
    }
}

/// ELF REL relocation entry.
#[repr(transparent)]
pub struct ElfRel {
    rel: <NativeElfLayout as ElfLayout>::Rel,
}

impl ElfRel {
    /// Returns the relocation type.
    #[inline]
    pub fn r_type(&self) -> usize {
        self.rel.r_info as usize & REL_MASK
    }

    /// Returns the symbol index.
    #[inline]
    pub fn r_symbol(&self) -> usize {
        self.rel.r_info as usize >> REL_BIT
    }

    /// Returns the relocation offset.
    #[inline]
    pub fn r_offset(&self) -> usize {
        self.rel.r_offset as usize
    }

    /// Returns the relocation addend.
    ///
    /// For REL entries, the addend is stored at the relocation offset.
    ///
    /// # Arguments
    /// * `base` - The base address to add to the offset.
    #[inline]
    pub fn r_addend(&self, base: usize) -> isize {
        let ptr = (self.r_offset() + base) as *mut usize;
        unsafe { ptr.read() as isize }
    }

    /// Sets the relocation offset.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    #[cfg(feature = "object")]
    #[cfg_attr(
        all(not(target_arch = "x86"), not(target_arch = "arm")),
        allow(dead_code)
    )]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rel.r_offset = offset as _;
    }
}

/// ELF program header describing segments to be loaded into memory.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfPhdr {
    phdr: <NativeElfLayout as ElfLayout>::Phdr,
}

impl ElfPhdr {
    /// Returns the parsed ELF program type of this header.
    #[inline]
    pub const fn program_type(&self) -> ElfProgramType {
        ElfProgramType::new(self.phdr.p_type)
    }

    /// Returns the parsed ELF program flags of this header.
    #[inline]
    pub fn flags(&self) -> ElfProgramFlags {
        ElfProgramFlags::from_bits_retain(self.phdr.p_flags)
    }

    /// Returns the segment file offset (`p_offset`) as a native-sized value.
    #[inline]
    pub fn p_offset(&self) -> usize {
        self.phdr.p_offset as usize
    }

    /// Returns the segment virtual address (`p_vaddr`) as a native-sized value.
    #[inline]
    pub fn p_vaddr(&self) -> usize {
        self.phdr.p_vaddr as usize
    }

    /// Returns the segment physical address (`p_paddr`) as a native-sized value.
    #[inline]
    pub fn p_paddr(&self) -> usize {
        self.phdr.p_paddr as usize
    }

    /// Returns the segment size in the file (`p_filesz`) as a native-sized value.
    #[inline]
    pub fn p_filesz(&self) -> usize {
        self.phdr.p_filesz as usize
    }

    /// Returns the segment size in memory (`p_memsz`) as a native-sized value.
    #[inline]
    pub fn p_memsz(&self) -> usize {
        self.phdr.p_memsz as usize
    }

    /// Returns the segment alignment (`p_align`) as a native-sized value.
    #[inline]
    pub fn p_align(&self) -> usize {
        self.phdr.p_align as usize
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

impl Clone for ElfPhdr {
    fn clone(&self) -> Self {
        let mut phdr: <NativeElfLayout as ElfLayout>::Phdr = unsafe { core::mem::zeroed() };
        phdr.p_type = self.phdr.p_type;
        phdr.p_flags = self.phdr.p_flags;
        phdr.p_align = self.phdr.p_align;
        phdr.p_offset = self.phdr.p_offset;
        phdr.p_vaddr = self.phdr.p_vaddr;
        phdr.p_paddr = self.phdr.p_paddr;
        phdr.p_filesz = self.phdr.p_filesz;
        phdr.p_memsz = self.phdr.p_memsz;
        Self { phdr }
    }
}

// Architecture-specific relocation entry type.
//
// This selects the appropriate relocation entry type based on the target
// architecture:
// - For x86 and ARM architectures: ElfRel (implicit addends)
// - For other architectures: ElfRela (explicit addends)
//
// This allows code to work with relocations in a generic way without needing to
// know the specific architecture details.
#[cfg(any(target_arch = "x86", target_arch = "arm"))]
pub type ElfRelType = ElfRel;
#[cfg(all(not(target_arch = "x86"), not(target_arch = "arm")))]
pub type ElfRelType = ElfRela;

#[cfg(feature = "object")]
pub(crate) const ELF_REL_SECTION_TYPE: ElfSectionType =
    if cfg!(any(target_arch = "x86", target_arch = "arm")) {
        ElfSectionType::REL
    } else {
        ElfSectionType::RELA
    };

impl ElfRelType {
    /// Return a human readable relocation type name for the current arch
    #[inline]
    pub fn r_type_str(&self) -> &'static str {
        let r_type = self.r_type();
        rel_type_to_str(r_type)
    }
}
