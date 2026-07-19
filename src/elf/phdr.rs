//! Program-header related ELF types.
//!
//! This module contains program-header views and storage used while loading ELF segments.

use super::{
    layout::{ElfLayout, NativeElfLayout},
    raw::ElfPhdrRaw,
};
use crate::memory::{MappedView, VmOffset};
use alloc::vec::Vec;
use bitflags::bitflags;
use core::fmt::{self, Display};
use elf::abi::*;

/// Semantic wrapper for the ELF `p_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfProgramType(u32);

impl ElfProgramType {
    /// `PT_NULL`: unused program-header entry.
    pub const NULL: Self = Self(PT_NULL);
    /// `PT_LOAD`: loadable segment.
    pub const LOAD: Self = Self(PT_LOAD);
    /// `PT_DYNAMIC`: dynamic-section segment.
    pub const DYNAMIC: Self = Self(PT_DYNAMIC);
    /// `PT_INTERP`: interpreter path segment.
    pub const INTERP: Self = Self(PT_INTERP);
    /// `PT_NOTE`: note segment.
    pub const NOTE: Self = Self(PT_NOTE);
    /// `PT_SHLIB`: reserved segment type.
    pub const SHLIB: Self = Self(PT_SHLIB);
    /// `PT_PHDR`: program-header table segment.
    pub const PHDR: Self = Self(PT_PHDR);
    /// `PT_TLS`: thread-local storage template segment.
    pub const TLS: Self = Self(PT_TLS);
    /// `PT_GNU_EH_FRAME`: GNU exception-frame header segment.
    pub const GNU_EH_FRAME: Self = Self(PT_GNU_EH_FRAME);
    /// `PT_GNU_PROPERTY`: GNU property note segment.
    pub const GNU_PROPERTY: Self = Self(PT_GNU_PROPERTY);
    /// `PT_GNU_STACK`: GNU stack permission segment.
    pub const GNU_STACK: Self = Self(PT_GNU_STACK);
    /// `PT_GNU_RELRO`: GNU RELRO segment.
    pub const GNU_RELRO: Self = Self(PT_GNU_RELRO);

    /// Creates a program type wrapper from a raw `p_type` value.
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `p_type` value.
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
            PT_GNU_PROPERTY => f.write_str("PT_GNU_PROPERTY"),
            PT_GNU_STACK => f.write_str("PT_GNU_STACK"),
            PT_GNU_RELRO => f.write_str("PT_GNU_RELRO"),
            raw => write!(f, "unknown ELF program type {raw}"),
        }
    }
}

bitflags! {
    /// Bitflags wrapper for the ELF `p_flags` field.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ElfProgramFlags: u32 {
        /// Segment is executable.
        const EXEC = PF_X;
        /// Segment is writable.
        const WRITE = PF_W;
        /// Segment is readable.
        const READ = PF_R;
    }
}

/// ELF program header describing segments to be loaded into memory.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfPhdr<L: ElfLayout = NativeElfLayout> {
    phdr: L::Phdr,
}

impl<L: ElfLayout> ElfPhdr<L> {
    /// Creates an owned ELF program header from native-sized field values.
    #[inline]
    // Mirrors the ELF program-header field list.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        program_type: ElfProgramType,
        flags: ElfProgramFlags,
        p_offset: usize,
        p_vaddr: VmOffset,
        p_paddr: usize,
        p_filesz: usize,
        p_memsz: usize,
        p_align: usize,
    ) -> Self {
        let mut phdr: L::Phdr = unsafe { core::mem::zeroed() };
        phdr.set_p_type(program_type.raw());
        phdr.set_p_flags(flags.bits());
        phdr.set_p_offset(p_offset);
        phdr.set_p_vaddr(p_vaddr.get());
        phdr.set_p_paddr(p_paddr);
        phdr.set_p_filesz(p_filesz);
        phdr.set_p_memsz(p_memsz);
        phdr.set_p_align(p_align);
        Self { phdr }
    }

    /// Returns the parsed ELF program type of this header.
    #[inline]
    pub fn program_type(&self) -> ElfProgramType {
        ElfProgramType::new(self.phdr.p_type())
    }

    /// Returns the parsed ELF program flags of this header.
    #[inline]
    pub fn flags(&self) -> ElfProgramFlags {
        ElfProgramFlags::from_bits_retain(self.phdr.p_flags())
    }

    /// Returns the segment file offset (`p_offset`) as a native-sized value.
    #[inline]
    pub fn p_offset(&self) -> usize {
        self.phdr.p_offset()
    }

    /// Returns the segment virtual address (`p_vaddr`) as an image virtual offset.
    #[inline]
    pub fn p_vaddr(&self) -> VmOffset {
        VmOffset::new(self.phdr.p_vaddr())
    }

    /// Returns the segment physical address (`p_paddr`) as a native-sized value.
    #[inline]
    pub fn p_paddr(&self) -> usize {
        self.phdr.p_paddr()
    }

    /// Returns the segment size in the file (`p_filesz`) as a native-sized value.
    #[inline]
    pub fn p_filesz(&self) -> usize {
        self.phdr.p_filesz()
    }

    /// Returns the segment size in memory (`p_memsz`) as a native-sized value.
    #[inline]
    pub fn p_memsz(&self) -> usize {
        self.phdr.p_memsz()
    }

    /// Returns the segment alignment (`p_align`) as a native-sized value.
    #[inline]
    pub fn p_align(&self) -> usize {
        self.phdr.p_align()
    }

    /// Sets the program type (`p_type`).
    #[inline]
    pub fn set_program_type(&mut self, program_type: ElfProgramType) {
        self.phdr.set_p_type(program_type.raw());
    }

    /// Sets the program flags (`p_flags`).
    #[inline]
    pub fn set_flags(&mut self, flags: ElfProgramFlags) {
        self.phdr.set_p_flags(flags.bits());
    }

    /// Sets the segment file offset (`p_offset`).
    #[inline]
    pub fn set_p_offset(&mut self, p_offset: usize) {
        self.phdr.set_p_offset(p_offset);
    }

    /// Sets the segment virtual address (`p_vaddr`).
    #[inline]
    pub fn set_p_vaddr(&mut self, p_vaddr: VmOffset) {
        self.phdr.set_p_vaddr(p_vaddr.get());
    }

    /// Sets the segment physical address (`p_paddr`).
    #[inline]
    pub fn set_p_paddr(&mut self, p_paddr: usize) {
        self.phdr.set_p_paddr(p_paddr);
    }

    /// Sets the segment size in the file (`p_filesz`).
    #[inline]
    pub fn set_p_filesz(&mut self, p_filesz: usize) {
        self.phdr.set_p_filesz(p_filesz);
    }

    /// Sets the segment size in memory (`p_memsz`).
    #[inline]
    pub fn set_p_memsz(&mut self, p_memsz: usize) {
        self.phdr.set_p_memsz(p_memsz);
    }

    /// Sets the segment alignment (`p_align`).
    #[inline]
    pub fn set_p_align(&mut self, p_align: usize) {
        self.phdr.set_p_align(p_align);
    }
}

impl<L: ElfLayout> Clone for ElfPhdr<L> {
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
pub(crate) enum ElfPhdrs<L: ElfLayout = NativeElfLayout> {
    /// Program headers borrowed from mapped memory
    Mapped(MappedView<ElfPhdr<L>>),

    /// Program headers stored in a vector
    Vec(Vec<ElfPhdr<L>>),
}

impl<L: ElfLayout> ElfPhdrs<L> {
    pub(crate) fn as_slice(&self) -> &[ElfPhdr<L>] {
        match self {
            ElfPhdrs::Mapped(phdrs) => phdrs.as_slice(),
            ElfPhdrs::Vec(phdrs) => phdrs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ElfPhdr, ElfProgramFlags, ElfProgramType};
    use crate::memory::VmOffset;

    #[test]
    fn owned_phdr_round_trips_and_mutates() {
        let mut phdr: ElfPhdr = ElfPhdr::new(
            ElfProgramType::LOAD,
            ElfProgramFlags::READ | ElfProgramFlags::WRITE,
            1,
            VmOffset::new(2),
            3,
            4,
            5,
            6,
        );

        assert_eq!(phdr.program_type(), ElfProgramType::LOAD);
        assert_eq!(phdr.flags(), ElfProgramFlags::READ | ElfProgramFlags::WRITE);
        assert_eq!(phdr.p_offset(), 1);
        assert_eq!(phdr.p_vaddr(), VmOffset::new(2));
        assert_eq!(phdr.p_paddr(), 3);
        assert_eq!(phdr.p_filesz(), 4);
        assert_eq!(phdr.p_memsz(), 5);
        assert_eq!(phdr.p_align(), 6);

        phdr.set_program_type(ElfProgramType::GNU_PROPERTY);
        phdr.set_flags(ElfProgramFlags::READ);
        phdr.set_p_offset(7);
        phdr.set_p_vaddr(VmOffset::new(8));
        phdr.set_p_paddr(9);
        phdr.set_p_filesz(10);
        phdr.set_p_memsz(11);
        phdr.set_p_align(12);

        assert_eq!(phdr.program_type(), ElfProgramType::GNU_PROPERTY);
        assert_eq!(phdr.flags(), ElfProgramFlags::READ);
        assert_eq!(phdr.p_offset(), 7);
        assert_eq!(phdr.p_vaddr(), VmOffset::new(8));
        assert_eq!(phdr.p_paddr(), 9);
        assert_eq!(phdr.p_filesz(), 10);
        assert_eq!(phdr.p_memsz(), 11);
        assert_eq!(phdr.p_align(), 12);

        phdr.set_program_type(ElfProgramType::GNU_STACK);
        assert_eq!(phdr.program_type(), ElfProgramType::GNU_STACK);
    }
}
