//! Program-header related ELF types.
//!
//! This module contains the semantic wrapper types for ELF program headers,
//! including `ElfProgramType`, `ElfProgramFlags`, `ElfPhdr`, and `ElfPhdrs`.

use alloc::vec::Vec;
use bitflags::bitflags;
use core::fmt::{self, Display};
use elf::abi::{
    PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_INTERP, PT_LOAD, PT_NOTE,
    PT_NULL, PT_PHDR, PT_SHLIB, PT_TLS,
};

use super::defs::{ElfLayout, NativeElfLayout};

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

/// Internal representation of ELF program headers
#[derive(Clone)]
pub(crate) enum ElfPhdrs {
    /// Program headers mapped from memory
    Mmap(&'static [ElfPhdr]),

    /// Program headers stored in a vector
    Vec(Vec<ElfPhdr>),
}

impl ElfPhdrs {
    pub(crate) fn as_slice(&self) -> &[ElfPhdr] {
        match self {
            ElfPhdrs::Mmap(phdrs) => phdrs,
            ElfPhdrs::Vec(phdrs) => phdrs,
        }
    }
}
