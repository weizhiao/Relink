//! Program-header related ELF types.
//!
//! This module contains program-header views and storage used while loading ELF segments.

use super::defs::{ElfLayout, ElfPhdrRaw, ElfProgramFlags, ElfProgramType, NativeElfLayout};
use alloc::vec::Vec;

/// ELF program header describing segments to be loaded into memory.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfPhdr<L: ElfLayout = NativeElfLayout> {
    phdr: L::Phdr,
}

impl<L: ElfLayout> ElfPhdr<L> {
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
        let mut phdr: L::Phdr = unsafe { core::mem::zeroed() };
        phdr.set_p_type(program_type.raw());
        phdr.set_p_flags(flags.bits());
        phdr.set_p_offset(p_offset);
        phdr.set_p_vaddr(p_vaddr);
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

    /// Returns the segment virtual address (`p_vaddr`) as a native-sized value.
    #[inline]
    pub fn p_vaddr(&self) -> usize {
        self.phdr.p_vaddr()
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
    pub fn set_p_vaddr(&mut self, p_vaddr: usize) {
        self.phdr.set_p_vaddr(p_vaddr);
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
    /// Program headers mapped from memory
    Mmap(&'static [ElfPhdr<L>]),

    /// Program headers stored in a vector
    Vec(Vec<ElfPhdr<L>>),
}

impl<L: ElfLayout> ElfPhdrs<L> {
    pub(crate) fn as_slice(&self) -> &[ElfPhdr<L>] {
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
        let mut phdr: ElfPhdr = ElfPhdr::new(
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
