//! ELF header parsing and validation
//!
//! This module provides functionality for parsing and validating ELF headers,
//! which contain essential metadata about ELF files such as architecture,
//! file type, and section/program header information.

use crate::{
    ParseEhdrError, ParsePhdrError, Result,
    arch::EM_ARCH,
    elf::{E_CLASS, ElfClass, ElfEhdr, ElfFileType, ElfMachine, ElfPhdr, ElfShdr},
};
use core::{mem::size_of, ops::Deref};
use elf::abi::{EI_CLASS, EI_VERSION, ELFMAGIC, ET_DYN, ET_EXEC, EV_CURRENT};

/// A wrapper around the ELF header structure
///
/// This structure provides safe access to ELF header data with validation
/// to ensure the ELF file is compatible with the target architecture
/// and follows the expected format.
#[repr(transparent)]
pub struct ElfHeader {
    /// The underlying ELF header structure
    ehdr: ElfEhdr,
}

impl Deref for ElfHeader {
    type Target = ElfEhdr;

    /// Dereferences to the underlying ELF header structure
    ///
    /// This implementation allows direct access to the fields of the
    /// underlying Ehdr structure through the ElfHeader wrapper.
    fn deref(&self) -> &Self::Target {
        &self.ehdr
    }
}

impl ElfHeader {
    #[inline]
    pub(crate) fn from_raw(ehdr: ElfEhdr) -> Result<Self> {
        let ehdr = Self { ehdr };
        ehdr.validate()?;
        Ok(ehdr)
    }

    /// Returns `true` if the ELF file is a dynamic library (shared object).
    #[inline]
    pub fn is_dylib(&self) -> bool {
        self.ehdr.e_type == ET_DYN
    }

    /// Returns `true` if the ELF file is an executable.
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.ehdr.e_type == ET_EXEC || self.ehdr.e_type == ET_DYN
    }

    /// Returns the parsed ELF class of this header.
    #[inline]
    pub const fn class(&self) -> ElfClass {
        ElfClass::new(self.ehdr.e_ident[EI_CLASS])
    }

    /// Returns the parsed ELF machine type of this header.
    #[inline]
    pub const fn machine(&self) -> ElfMachine {
        ElfMachine::new(self.ehdr.e_machine)
    }

    /// Returns the parsed ELF file type of this header.
    #[inline]
    pub const fn file_type(&self) -> ElfFileType {
        ElfFileType::new(self.ehdr.e_type)
    }

    /// Validates the ELF header magic, class, version, and architecture.
    pub fn validate(&self) -> Result<()> {
        // Check ELF magic bytes
        if self.e_ident[0..4] != ELFMAGIC {
            return Err(ParseEhdrError::InvalidMagic.into());
        }

        // Check file class (32-bit vs 64-bit)
        let class = self.class();
        if class.raw() != E_CLASS {
            return Err(ParseEhdrError::FileClassMismatch {
                expected: ElfClass::new(E_CLASS),
                found: class,
            }
            .into());
        }

        // Check ELF version
        if self.e_ident[EI_VERSION] != EV_CURRENT {
            return Err(ParseEhdrError::InvalidVersion.into());
        }

        // Check machine architecture
        let machine = self.machine();
        if machine.raw() != EM_ARCH {
            return Err(ParseEhdrError::FileArchMismatch {
                expected: ElfMachine::new(EM_ARCH),
                found: machine,
            }
            .into());
        }

        Ok(())
    }

    /// Returns the number of program headers.
    #[inline]
    pub fn e_phnum(&self) -> usize {
        self.ehdr.e_phnum as usize
    }

    /// Returns the size of each program header entry.
    #[inline]
    pub fn e_phentsize(&self) -> usize {
        self.ehdr.e_phentsize as usize
    }

    /// Returns the file offset of the program header table.
    #[inline]
    pub fn e_phoff(&self) -> usize {
        self.ehdr.e_phoff as usize
    }

    /// Returns the file offset of the section header table.
    #[inline]
    pub fn e_shoff(&self) -> usize {
        self.ehdr.e_shoff as usize
    }

    /// Returns the size of each section header entry.
    #[inline]
    pub fn e_shentsize(&self) -> usize {
        self.ehdr.e_shentsize as usize
    }

    /// Returns the number of section headers.
    #[inline]
    pub fn e_shnum(&self) -> usize {
        self.ehdr.e_shnum as usize
    }

    /// Returns the `(start, end)` file offsets of the program header table.
    #[inline]
    pub fn phdr_range(&self) -> (usize, usize) {
        let phdrs_size = self.e_phentsize() * self.e_phnum();
        let phdr_start = self.e_phoff();
        let phdr_end = phdr_start + phdrs_size;
        (phdr_start, phdr_end)
    }

    /// Returns the checked `(start, size)` layout for the program header table.
    ///
    /// This validates entry-size compatibility and overflow-prone arithmetic.
    #[inline]
    pub(crate) fn checked_phdr_layout(&self) -> Result<Option<(usize, usize)>> {
        let entsize = self.e_phentsize();
        if entsize != size_of::<ElfPhdr>() {
            return Err(ParsePhdrError::MalformedProgramHeaders.into());
        }

        let count = self.e_phnum();
        let size = entsize
            .checked_mul(count)
            .ok_or(ParsePhdrError::MalformedProgramHeaders)?;
        if size == 0 {
            return Ok(None);
        }

        let start = self.e_phoff();
        let _end = start
            .checked_add(size)
            .ok_or(ParsePhdrError::MalformedProgramHeaders)?;
        Ok(Some((start, size)))
    }

    /// Returns the `(start, end)` file offsets of the section header table.
    #[inline]
    pub fn shdr_range(&self) -> (usize, usize) {
        let shdrs_size = self.e_shentsize() * self.e_shnum();
        let shdr_start = self.e_shoff();
        let shdr_end = shdr_start + shdrs_size;
        (shdr_start, shdr_end)
    }

    /// Returns the checked `(start, size)` layout for the section header table.
    ///
    /// This validates entry-size compatibility and overflow-prone arithmetic.
    #[inline]
    #[cfg_attr(not(feature = "object"), allow(dead_code))]
    pub(crate) fn checked_shdr_layout(&self) -> Result<Option<(usize, usize)>> {
        let entsize = self.e_shentsize();
        if entsize != size_of::<ElfShdr>() {
            return Err(ParseEhdrError::MissingSectionHeaders.into());
        }

        let count = self.e_shnum();
        let size = entsize
            .checked_mul(count)
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        if size == 0 {
            return Ok(None);
        }

        let start = self.e_shoff();
        let _end = start
            .checked_add(size)
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        Ok(Some((start, size)))
    }
}
