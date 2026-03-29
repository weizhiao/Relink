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
    /// Creates an owned ELF program header from native-sized field values.
    #[inline]
    pub fn new(
        program_type: ElfProgramType,
        flags: ElfProgramFlags,
        p_offset: usize,
        p_vaddr: usize,
        p_paddr: usize,
        p_filesz: usize,
        p_memsz: usize,
        p_align: usize,
    ) -> Self {
        let mut phdr: <NativeElfLayout as ElfLayout>::Phdr = unsafe { core::mem::zeroed() };
        phdr.p_type = program_type.raw();
        phdr.p_flags = flags.bits();
        phdr.p_offset = p_offset as _;
        phdr.p_vaddr = p_vaddr as _;
        phdr.p_paddr = p_paddr as _;
        phdr.p_filesz = p_filesz as _;
        phdr.p_memsz = p_memsz as _;
        phdr.p_align = p_align as _;
        Self { phdr }
    }

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

    /// Sets the program type (`p_type`).
    #[inline]
    pub fn set_program_type(&mut self, program_type: ElfProgramType) {
        self.phdr.p_type = program_type.raw();
    }

    /// Sets the program flags (`p_flags`).
    #[inline]
    pub fn set_flags(&mut self, flags: ElfProgramFlags) {
        self.phdr.p_flags = flags.bits();
    }

    /// Sets the segment file offset (`p_offset`).
    #[inline]
    pub fn set_p_offset(&mut self, p_offset: usize) {
        self.phdr.p_offset = p_offset as _;
    }

    /// Sets the segment virtual address (`p_vaddr`).
    #[inline]
    pub fn set_p_vaddr(&mut self, p_vaddr: usize) {
        self.phdr.p_vaddr = p_vaddr as _;
    }

    /// Sets the segment physical address (`p_paddr`).
    #[inline]
    pub fn set_p_paddr(&mut self, p_paddr: usize) {
        self.phdr.p_paddr = p_paddr as _;
    }

    /// Sets the segment size in the file (`p_filesz`).
    #[inline]
    pub fn set_p_filesz(&mut self, p_filesz: usize) {
        self.phdr.p_filesz = p_filesz as _;
    }

    /// Sets the segment size in memory (`p_memsz`).
    #[inline]
    pub fn set_p_memsz(&mut self, p_memsz: usize) {
        self.phdr.p_memsz = p_memsz as _;
    }

    /// Sets the segment alignment (`p_align`).
    #[inline]
    pub fn set_p_align(&mut self, p_align: usize) {
        self.phdr.p_align = p_align as _;
    }
}

impl Clone for ElfPhdr {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(
            self.program_type(),
            self.flags(),
            self.p_offset(),
            self.p_vaddr(),
            self.p_paddr(),
            self.p_filesz(),
            self.p_memsz(),
            self.p_align(),
        )
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

#[cfg(test)]
mod tests {
    use super::{ElfPhdr, ElfProgramFlags, ElfProgramType};

    #[test]
    fn owned_phdr_round_trips_and_mutates() {
        let mut phdr = ElfPhdr::new(
            ElfProgramType::LOAD,
            ElfProgramFlags::READ | ElfProgramFlags::WRITE,
            1,
            2,
            3,
            4,
            5,
            6,
        );

        assert_eq!(phdr.program_type(), ElfProgramType::LOAD);
        assert_eq!(phdr.flags(), ElfProgramFlags::READ | ElfProgramFlags::WRITE);
        assert_eq!(phdr.p_offset(), 1);
        assert_eq!(phdr.p_vaddr(), 2);
        assert_eq!(phdr.p_paddr(), 3);
        assert_eq!(phdr.p_filesz(), 4);
        assert_eq!(phdr.p_memsz(), 5);
        assert_eq!(phdr.p_align(), 6);

        phdr.set_program_type(ElfProgramType::DYNAMIC);
        phdr.set_flags(ElfProgramFlags::READ);
        phdr.set_p_offset(7);
        phdr.set_p_vaddr(8);
        phdr.set_p_paddr(9);
        phdr.set_p_filesz(10);
        phdr.set_p_memsz(11);
        phdr.set_p_align(12);

        assert_eq!(phdr.program_type(), ElfProgramType::DYNAMIC);
        assert_eq!(phdr.flags(), ElfProgramFlags::READ);
        assert_eq!(phdr.p_offset(), 7);
        assert_eq!(phdr.p_vaddr(), 8);
        assert_eq!(phdr.p_paddr(), 9);
        assert_eq!(phdr.p_filesz(), 10);
        assert_eq!(phdr.p_memsz(), 11);
        assert_eq!(phdr.p_align(), 12);
    }
}
