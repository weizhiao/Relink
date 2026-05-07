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

use crate::{arch::NativeArch, relocation::RelocationArch};

use super::shdr::ElfSectionType;
pub(crate) use super::symbol::Elf32Sym;

pub trait ElfWord: Copy + 'static {
    const BITS: usize;

    fn from_usize(value: usize) -> Self;
    fn to_usize(self) -> usize;
    fn to_u64(self) -> u64;
}

impl ElfWord for u32 {
    const BITS: usize = u32::BITS as usize;

    #[inline]
    fn from_usize(value: usize) -> Self {
        value as Self
    }

    #[inline]
    fn to_usize(self) -> usize {
        self as usize
    }

    #[inline]
    fn to_u64(self) -> u64 {
        self as u64
    }
}

impl ElfWord for u64 {
    const BITS: usize = u64::BITS as usize;

    #[inline]
    fn from_usize(value: usize) -> Self {
        value as Self
    }

    #[inline]
    fn to_usize(self) -> usize {
        self as usize
    }

    #[inline]
    fn to_u64(self) -> u64 {
        self
    }
}

pub trait ElfEhdrRaw: 'static {
    fn e_ident(&self) -> &[u8; elf::abi::EI_NIDENT];
    fn e_type(&self) -> u16;
    fn e_machine(&self) -> u16;
    fn e_entry(&self) -> usize;
    fn e_phoff(&self) -> usize;
    fn e_shoff(&self) -> usize;
    fn e_phentsize(&self) -> usize;
    fn e_phnum(&self) -> usize;
    fn e_shentsize(&self) -> usize;
    fn e_shnum(&self) -> usize;
    fn e_shstrndx(&self) -> usize;
}

macro_rules! impl_ehdr_raw {
    ($ty:ty) => {
        impl ElfEhdrRaw for $ty {
            #[inline]
            fn e_ident(&self) -> &[u8; elf::abi::EI_NIDENT] {
                &self.e_ident
            }

            #[inline]
            fn e_type(&self) -> u16 {
                self.e_type
            }

            #[inline]
            fn e_machine(&self) -> u16 {
                self.e_machine
            }

            #[inline]
            fn e_entry(&self) -> usize {
                self.e_entry as usize
            }

            #[inline]
            fn e_phoff(&self) -> usize {
                self.e_phoff as usize
            }

            #[inline]
            fn e_shoff(&self) -> usize {
                self.e_shoff as usize
            }

            #[inline]
            fn e_phentsize(&self) -> usize {
                self.e_phentsize as usize
            }

            #[inline]
            fn e_phnum(&self) -> usize {
                self.e_phnum as usize
            }

            #[inline]
            fn e_shentsize(&self) -> usize {
                self.e_shentsize as usize
            }

            #[inline]
            fn e_shnum(&self) -> usize {
                self.e_shnum as usize
            }

            #[inline]
            fn e_shstrndx(&self) -> usize {
                self.e_shstrndx as usize
            }
        }
    };
}

impl_ehdr_raw!(elf::file::Elf32_Ehdr);
impl_ehdr_raw!(elf::file::Elf64_Ehdr);

pub trait ElfPhdrRaw: 'static {
    fn set_p_type(&mut self, value: u32);
    fn set_p_flags(&mut self, value: u32);
    fn set_p_offset(&mut self, value: usize);
    fn set_p_vaddr(&mut self, value: usize);
    fn set_p_paddr(&mut self, value: usize);
    fn set_p_filesz(&mut self, value: usize);
    fn set_p_memsz(&mut self, value: usize);
    fn set_p_align(&mut self, value: usize);

    fn p_type(&self) -> u32;
    fn p_flags(&self) -> u32;
    fn p_offset(&self) -> usize;
    fn p_vaddr(&self) -> usize;
    fn p_paddr(&self) -> usize;
    fn p_filesz(&self) -> usize;
    fn p_memsz(&self) -> usize;
    fn p_align(&self) -> usize;
}

macro_rules! impl_phdr_raw {
    ($ty:ty) => {
        impl ElfPhdrRaw for $ty {
            #[inline]
            fn set_p_type(&mut self, value: u32) {
                self.p_type = value;
            }

            #[inline]
            fn set_p_flags(&mut self, value: u32) {
                self.p_flags = value;
            }

            #[inline]
            fn set_p_offset(&mut self, value: usize) {
                self.p_offset = value as _;
            }

            #[inline]
            fn set_p_vaddr(&mut self, value: usize) {
                self.p_vaddr = value as _;
            }

            #[inline]
            fn set_p_paddr(&mut self, value: usize) {
                self.p_paddr = value as _;
            }

            #[inline]
            fn set_p_filesz(&mut self, value: usize) {
                self.p_filesz = value as _;
            }

            #[inline]
            fn set_p_memsz(&mut self, value: usize) {
                self.p_memsz = value as _;
            }

            #[inline]
            fn set_p_align(&mut self, value: usize) {
                self.p_align = value as _;
            }

            #[inline]
            fn p_type(&self) -> u32 {
                self.p_type
            }

            #[inline]
            fn p_flags(&self) -> u32 {
                self.p_flags
            }

            #[inline]
            fn p_offset(&self) -> usize {
                self.p_offset as usize
            }

            #[inline]
            fn p_vaddr(&self) -> usize {
                self.p_vaddr as usize
            }

            #[inline]
            fn p_paddr(&self) -> usize {
                self.p_paddr as usize
            }

            #[inline]
            fn p_filesz(&self) -> usize {
                self.p_filesz as usize
            }

            #[inline]
            fn p_memsz(&self) -> usize {
                self.p_memsz as usize
            }

            #[inline]
            fn p_align(&self) -> usize {
                self.p_align as usize
            }
        }
    };
}

impl_phdr_raw!(elf::segment::Elf32_Phdr);
impl_phdr_raw!(elf::segment::Elf64_Phdr);

#[cfg_attr(not(feature = "object"), allow(dead_code))]
pub trait ElfShdrRaw: 'static {
    fn set_sh_name(&mut self, value: u32);
    fn set_sh_type(&mut self, value: u32);
    fn set_sh_flags(&mut self, value: u64);
    fn set_sh_addr(&mut self, value: usize);
    fn add_sh_addr(&mut self, value: usize);
    fn set_sh_offset(&mut self, value: usize);
    fn set_sh_size(&mut self, value: usize);
    fn set_sh_link(&mut self, value: u32);
    fn set_sh_info(&mut self, value: u32);
    fn set_sh_addralign(&mut self, value: usize);
    fn set_sh_entsize(&mut self, value: usize);

    fn sh_name(&self) -> u32;
    fn sh_type(&self) -> u32;
    fn sh_flags(&self) -> u64;
    fn sh_addr(&self) -> usize;
    fn sh_offset(&self) -> usize;
    fn sh_size(&self) -> usize;
    fn sh_link(&self) -> u32;
    fn sh_info(&self) -> u32;
    fn sh_addralign(&self) -> usize;
    fn sh_entsize(&self) -> usize;
}

macro_rules! impl_shdr_raw {
    ($ty:ty) => {
        impl ElfShdrRaw for $ty {
            #[inline]
            fn set_sh_name(&mut self, value: u32) {
                self.sh_name = value;
            }

            #[inline]
            fn set_sh_type(&mut self, value: u32) {
                self.sh_type = value;
            }

            #[inline]
            fn set_sh_flags(&mut self, value: u64) {
                self.sh_flags = value as _;
            }

            #[inline]
            fn set_sh_addr(&mut self, value: usize) {
                self.sh_addr = value as _;
            }

            #[inline]
            fn add_sh_addr(&mut self, value: usize) {
                self.sh_addr = self.sh_addr.wrapping_add(value as _);
            }

            #[inline]
            fn set_sh_offset(&mut self, value: usize) {
                self.sh_offset = value as _;
            }

            #[inline]
            fn set_sh_size(&mut self, value: usize) {
                self.sh_size = value as _;
            }

            #[inline]
            fn set_sh_link(&mut self, value: u32) {
                self.sh_link = value;
            }

            #[inline]
            fn set_sh_info(&mut self, value: u32) {
                self.sh_info = value;
            }

            #[inline]
            fn set_sh_addralign(&mut self, value: usize) {
                self.sh_addralign = value as _;
            }

            #[inline]
            fn set_sh_entsize(&mut self, value: usize) {
                self.sh_entsize = value as _;
            }

            #[inline]
            fn sh_name(&self) -> u32 {
                self.sh_name
            }

            #[inline]
            fn sh_type(&self) -> u32 {
                self.sh_type
            }

            #[inline]
            fn sh_flags(&self) -> u64 {
                self.sh_flags as u64
            }

            #[inline]
            fn sh_addr(&self) -> usize {
                self.sh_addr as usize
            }

            #[inline]
            fn sh_offset(&self) -> usize {
                self.sh_offset as usize
            }

            #[inline]
            fn sh_size(&self) -> usize {
                self.sh_size as usize
            }

            #[inline]
            fn sh_link(&self) -> u32 {
                self.sh_link
            }

            #[inline]
            fn sh_info(&self) -> u32 {
                self.sh_info
            }

            #[inline]
            fn sh_addralign(&self) -> usize {
                self.sh_addralign as usize
            }

            #[inline]
            fn sh_entsize(&self) -> usize {
                self.sh_entsize as usize
            }
        }
    };
}

impl_shdr_raw!(elf::section::Elf32_Shdr);
impl_shdr_raw!(elf::section::Elf64_Shdr);

pub trait ElfDynRaw: 'static {
    fn set_d_tag(&mut self, value: i64);
    fn set_d_un(&mut self, value: usize);
    fn d_tag(&self) -> i64;
    fn d_un(&self) -> usize;
}

macro_rules! impl_dyn_raw {
    ($ty:ty) => {
        impl ElfDynRaw for $ty {
            #[inline]
            fn set_d_tag(&mut self, value: i64) {
                self.d_tag = value as _;
            }

            #[inline]
            fn set_d_un(&mut self, value: usize) {
                self.d_un = value as _;
            }

            #[inline]
            fn d_tag(&self) -> i64 {
                self.d_tag as i64
            }

            #[inline]
            fn d_un(&self) -> usize {
                self.d_un as usize
            }
        }
    };
}

impl_dyn_raw!(elf::dynamic::Elf32_Dyn);
impl_dyn_raw!(elf::dynamic::Elf64_Dyn);

pub trait ElfRelRaw: 'static {
    fn set_r_offset(&mut self, value: usize);
    fn r_offset(&self) -> usize;
    fn r_info(&self) -> usize;
}

macro_rules! impl_rel_raw {
    ($ty:ty) => {
        impl ElfRelRaw for $ty {
            #[inline]
            fn set_r_offset(&mut self, value: usize) {
                self.r_offset = value as _;
            }

            #[inline]
            fn r_offset(&self) -> usize {
                self.r_offset as usize
            }

            #[inline]
            fn r_info(&self) -> usize {
                self.r_info as usize
            }
        }
    };
}

impl_rel_raw!(elf::relocation::Elf32_Rel);
impl_rel_raw!(elf::relocation::Elf64_Rel);

pub trait ElfRelaRaw: ElfRelRaw {
    fn set_r_addend(&mut self, value: isize);
    fn r_addend(&self) -> isize;
}

macro_rules! impl_rela_raw {
    ($ty:ty) => {
        impl ElfRelRaw for $ty {
            #[inline]
            fn set_r_offset(&mut self, value: usize) {
                self.r_offset = value as _;
            }

            #[inline]
            fn r_offset(&self) -> usize {
                self.r_offset as usize
            }

            #[inline]
            fn r_info(&self) -> usize {
                self.r_info as usize
            }
        }

        impl ElfRelaRaw for $ty {
            #[inline]
            fn set_r_addend(&mut self, value: isize) {
                self.r_addend = value as _;
            }

            #[inline]
            fn r_addend(&self) -> isize {
                self.r_addend as isize
            }
        }
    };
}

impl_rela_raw!(elf::relocation::Elf32_Rela);
impl_rela_raw!(elf::relocation::Elf64_Rela);

pub trait ElfSymRaw: 'static {
    fn st_name(&self) -> usize;
    fn st_value(&self) -> usize;
    fn set_st_value(&mut self, value: usize);
    fn st_size(&self) -> usize;
    fn st_info(&self) -> u8;
    fn st_other(&self) -> u8;
    fn st_shndx(&self) -> u16;
}

macro_rules! impl_sym_raw {
    ($ty:ty) => {
        impl ElfSymRaw for $ty {
            #[inline]
            fn st_name(&self) -> usize {
                self.st_name as usize
            }

            #[inline]
            fn st_value(&self) -> usize {
                self.st_value as usize
            }

            #[inline]
            fn set_st_value(&mut self, value: usize) {
                self.st_value = value as _;
            }

            #[inline]
            fn st_size(&self) -> usize {
                self.st_size as usize
            }

            #[inline]
            fn st_info(&self) -> u8 {
                self.st_info
            }

            #[inline]
            fn st_other(&self) -> u8 {
                self.st_other
            }

            #[inline]
            fn st_shndx(&self) -> u16 {
                self.st_shndx as u16
            }
        }
    };
}

impl_sym_raw!(Elf32Sym);
impl_sym_raw!(elf::symbol::Elf64_Sym);

/// Groups the raw ELF types/constants selected for one ELF class.
pub trait ElfLayout: 'static {
    const E_CLASS: u8;
    const REL_MASK: usize;
    const REL_BIT: usize;
    const EHDR_SIZE: usize;

    type Phdr: ElfPhdrRaw;
    type Shdr: ElfShdrRaw;
    type Dyn: ElfDynRaw;
    type Ehdr: ElfEhdrRaw;
    type Rela: ElfRelaRaw;
    type Rel: ElfRelRaw;
    type Relr: ElfWord;
    type Word: ElfWord;
    type Sym: ElfSymRaw;
}

#[derive(Debug, Clone, Copy)]
pub struct Elf32Layout;

impl ElfLayout for Elf32Layout {
    const E_CLASS: u8 = elf::abi::ELFCLASS32;
    const REL_MASK: usize = 0xFF;
    const REL_BIT: usize = 8;
    const EHDR_SIZE: usize = core::mem::size_of::<Self::Ehdr>();

    type Phdr = elf::segment::Elf32_Phdr;
    type Shdr = elf::section::Elf32_Shdr;
    type Dyn = elf::dynamic::Elf32_Dyn;
    type Ehdr = elf::file::Elf32_Ehdr;
    type Rela = elf::relocation::Elf32_Rela;
    type Rel = elf::relocation::Elf32_Rel;
    type Relr = u32;
    type Word = u32;
    type Sym = Elf32Sym;
}

#[derive(Debug, Clone, Copy)]
pub struct Elf64Layout;

impl ElfLayout for Elf64Layout {
    const E_CLASS: u8 = elf::abi::ELFCLASS64;
    const REL_MASK: usize = 0xFFFFFFFF;
    const REL_BIT: usize = 32;
    const EHDR_SIZE: usize = core::mem::size_of::<Self::Ehdr>();

    type Phdr = elf::segment::Elf64_Phdr;
    type Shdr = elf::section::Elf64_Shdr;
    type Dyn = elf::dynamic::Elf64_Dyn;
    type Ehdr = elf::file::Elf64_Ehdr;
    type Rela = elf::relocation::Elf64_Rela;
    type Rel = elf::relocation::Elf64_Rel;
    type Relr = u64;
    type Word = u64;
    type Sym = elf::symbol::Elf64_Sym;
}

#[cfg(target_pointer_width = "64")]
pub type NativeElfLayout = Elf64Layout;
#[cfg(not(target_pointer_width = "64"))]
pub type NativeElfLayout = Elf32Layout;

pub(crate) type ElfEhdr = <NativeElfLayout as ElfLayout>::Ehdr;

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
pub struct ElfRelr<L: ElfLayout = NativeElfLayout> {
    relr: L::Relr,
}

impl<L: ElfLayout> ElfRelr<L> {
    /// Returns the value of the relocation entry.
    #[inline]
    pub fn value(&self) -> usize {
        self.relr.to_usize()
    }
}

/// Semantic wrapper for the ELF relocation type encoded in `r_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfRelocationType(u32);

impl ElfRelocationType {
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
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
pub struct ElfRela<L: ElfLayout = NativeElfLayout> {
    rela: L::Rela,
}

impl<L: ElfLayout> ElfRela<L> {
    /// Returns the relocation type.
    #[inline]
    pub fn r_type(&self) -> ElfRelocationType {
        ElfRelocationType::new((self.rela.r_info() & L::REL_MASK) as u32)
    }

    /// Returns the symbol index.
    #[inline]
    pub fn r_symbol(&self) -> usize {
        self.rela.r_info() >> L::REL_BIT
    }

    /// Returns the relocation offset.
    #[inline]
    pub fn r_offset(&self) -> usize {
        self.rela.r_offset()
    }

    /// Returns the relocation addend.
    #[inline]
    pub fn r_addend(&self, _base: usize) -> isize {
        self.rela.r_addend()
    }

    /// Sets the relocation offset.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rela.set_r_offset(offset);
    }

    /// Sets the relocation addend.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    pub(crate) fn set_addend(&mut self, _base: usize, addend: isize) {
        self.rela.set_r_addend(addend);
    }
}

/// ELF REL relocation entry.
#[repr(transparent)]
pub struct ElfRel<L: ElfLayout = NativeElfLayout> {
    rel: L::Rel,
}

impl<L: ElfLayout> ElfRel<L> {
    /// Returns the relocation type.
    #[inline]
    pub fn r_type(&self) -> ElfRelocationType {
        ElfRelocationType::new((self.rel.r_info() & L::REL_MASK) as u32)
    }

    /// Returns the symbol index.
    #[inline]
    pub fn r_symbol(&self) -> usize {
        self.rel.r_info() >> L::REL_BIT
    }

    /// Returns the relocation offset.
    #[inline]
    pub fn r_offset(&self) -> usize {
        self.rel.r_offset()
    }

    /// Returns the relocation addend.
    ///
    /// For REL entries, the addend is stored at the relocation offset.
    ///
    /// # Arguments
    /// * `base` - The base address to add to the offset.
    #[inline]
    pub fn r_addend(&self, base: usize) -> isize {
        let ptr = (self.r_offset() + base) as *const L::Word;
        unsafe { ptr.read_unaligned().to_usize() as isize }
    }

    /// Sets the relocation offset.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rel.set_r_offset(offset);
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
        let ptr = (self.r_offset() + base) as *mut L::Word;
        unsafe { ptr.write_unaligned(L::Word::from_usize(addend as usize)) };
    }
}

pub trait ElfRelEntry<L: ElfLayout = NativeElfLayout> {
    const SECTION_TYPE: ElfSectionType;
    const HAS_IMPLICIT_ADDEND: bool;

    fn r_type(&self) -> ElfRelocationType;
    fn r_symbol(&self) -> usize;
    fn r_offset(&self) -> usize;
    fn r_addend(&self, base: usize) -> isize;
    fn set_offset(&mut self, offset: usize);
    fn set_addend(&mut self, base: usize, addend: isize);
}

impl<L: ElfLayout> ElfRelEntry<L> for ElfRela<L> {
    const SECTION_TYPE: ElfSectionType = ElfSectionType::RELA;
    const HAS_IMPLICIT_ADDEND: bool = false;

    #[inline]
    fn r_type(&self) -> ElfRelocationType {
        self.r_type()
    }

    #[inline]
    fn r_symbol(&self) -> usize {
        self.r_symbol()
    }

    #[inline]
    fn r_offset(&self) -> usize {
        self.r_offset()
    }

    #[inline]
    fn r_addend(&self, base: usize) -> isize {
        self.r_addend(base)
    }

    #[inline]
    fn set_offset(&mut self, offset: usize) {
        self.set_offset(offset);
    }

    #[inline]
    fn set_addend(&mut self, base: usize, addend: isize) {
        self.set_addend(base, addend);
    }
}

impl<L: ElfLayout> ElfRelEntry<L> for ElfRel<L> {
    const SECTION_TYPE: ElfSectionType = ElfSectionType::REL;
    const HAS_IMPLICIT_ADDEND: bool = true;

    #[inline]
    fn r_type(&self) -> ElfRelocationType {
        self.r_type()
    }

    #[inline]
    fn r_symbol(&self) -> usize {
        self.r_symbol()
    }

    #[inline]
    fn r_offset(&self) -> usize {
        self.r_offset()
    }

    #[inline]
    fn r_addend(&self, base: usize) -> isize {
        self.r_addend(base)
    }

    #[inline]
    fn set_offset(&mut self, offset: usize) {
        self.set_offset(offset);
    }

    #[inline]
    fn set_addend(&mut self, base: usize, addend: isize) {
        self.set_addend(base, addend);
    }
}

pub type ElfRelType<Arch = NativeArch> = <Arch as RelocationArch>::Relocation;

#[cfg(feature = "object")]
pub(crate) const ELF_REL_SECTION_TYPE: ElfSectionType =
    <ElfRelType as ElfRelEntry<NativeElfLayout>>::SECTION_TYPE;
