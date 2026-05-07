//! ELF format definitions and utilities.
//!
//! This module provides core ELF (Executable and Linkable Format) data structures
//! and helper functions for parsing and manipulating ELF files. It includes
//! definitions for relocation entries, symbols, program headers, and section headers,
//! with support for both 32-bit and 64-bit ELF formats.

use core::fmt::{self, Display};
use elf::abi::{
    ELFCLASS32, ELFCLASS64, ELFCLASSNONE, EM_386, EM_AARCH64, EM_ARM, EM_RISCV, EM_X86_64, ET_CORE,
    ET_DYN, ET_EXEC, ET_NONE, ET_REL,
};

// All native relocation numbers come from the host's `RelocationArch` impl
// via [`crate::arch::NativeArch`]. Reading them through the trait keeps
// `ElfRelocationType` independent of which architecture is the host: no
// per-arch path needs to be wired here.
use crate::{arch::NativeArch, relocation::RelocationArch};

#[cfg(feature = "object")]
use super::shdr::ElfSectionType;
#[cfg(not(target_pointer_width = "64"))]
pub(crate) use super::symbol::Elf32Sym;

/// Groups the raw ELF types/constants selected for the current target.
///
/// Keeping this behind a single trait lets us centralize the pointer-width
/// mapping without forcing the rest of the module to become generic.
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

/// Semantic wrapper for the ELF relocation type encoded in `r_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfRelocationType(u32);

impl ElfRelocationType {
    pub const JUMP_SLOT: Self = <NativeArch as RelocationArch>::JUMP_SLOT;

    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Whether this is the ELF-standard "no relocation" entry (type 0 on
    /// every architecture).
    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Whether this is the host architecture's `RELATIVE` relocation.
    #[inline]
    pub fn is_relative(self) -> bool {
        self.0 == <NativeArch as RelocationArch>::RELATIVE.raw()
    }

    /// Whether this is the host architecture's `IRELATIVE` relocation.
    #[inline]
    pub fn is_irelative(self) -> bool {
        self.0 == <NativeArch as RelocationArch>::IRELATIVE.raw()
    }
}

impl From<u32> for ElfRelocationType {
    #[inline]
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<ElfRelocationType> for u32 {
    #[inline]
    fn from(value: ElfRelocationType) -> Self {
        value.raw()
    }
}

impl Display for ElfRelocationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<NativeArch as RelocationArch>::rel_type_to_str(*self))
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
    pub fn r_type(&self) -> ElfRelocationType {
        ElfRelocationType::new((self.rela.r_info as usize & REL_MASK) as u32)
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
    #[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rela.r_offset = offset as _;
    }

    /// Sets the relocation addend.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    pub(crate) fn set_addend(&mut self, _base: usize, addend: isize) {
        self.rela.r_addend = addend as _;
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
    pub fn r_type(&self) -> ElfRelocationType {
        ElfRelocationType::new((self.rel.r_info as usize & REL_MASK) as u32)
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
    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rel.r_offset = offset as _;
    }

    /// Sets the relocation addend.
    ///
    /// For REL entries, the addend is stored at the relocation offset.
    ///
    /// # Arguments
    /// * `base` - The base address to add to the offset.
    /// * `addend` - The new implicit addend value.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn set_addend(&mut self, base: usize, addend: isize) {
        let ptr = (self.r_offset() + base) as *mut usize;
        unsafe { ptr.write(addend as usize) };
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

