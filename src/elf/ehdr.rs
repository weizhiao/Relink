//! ELF header parsing and validation
//!
//! This module provides functionality for parsing and validating ELF headers,
//! which contain essential metadata about ELF files such as architecture,
//! file type, and section/program header information.

use crate::{
    Result,
    arch::EM_ARCH,
    elf::{E_CLASS, EHDR_SIZE, ElfEhdr},
    parse_ehdr_error,
};
use core::ops::Deref;
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

impl Clone for ElfHeader {
    /// Creates a copy of the ELF header
    ///
    /// This implementation manually clones each field of the ELF header
    /// to avoid potential issues with automatic derivation.
    fn clone(&self) -> Self {
        Self {
            ehdr: ElfEhdr {
                e_ident: self.e_ident,
                e_type: self.e_type,
                e_machine: self.e_machine,
                e_version: self.e_version,
                e_entry: self.e_entry,
                e_phoff: self.e_phoff,
                e_shoff: self.e_shoff,
                e_flags: self.e_flags,
                e_ehsize: self.e_ehsize,
                e_phentsize: self.e_phentsize,
                e_phnum: self.e_phnum,
                e_shentsize: self.e_shentsize,
                e_shnum: self.e_shnum,
                e_shstrndx: self.e_shstrndx,
            },
        }
    }
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
    /// Creates a new ElfHeader from raw data
    ///
    /// This function parses an ELF header from a byte slice and validates
    /// that it represents a valid ELF file compatible with the target
    /// architecture.
    ///
    /// # Arguments
    /// * `data` - A byte slice containing the ELF header data
    ///
    /// # Returns
    /// * `Ok(&ElfHeader)` - A reference to the parsed and validated ELF header
    /// * `Err(Error)` - If the data does not represent a valid ELF header
    ///
    /// # Safety
    /// The caller must ensure that the data slice contains at least
    /// EHDR_SIZE bytes of valid ELF header data.
    pub fn new(data: &[u8]) -> Result<&Self> {
        debug_assert!(data.len() >= EHDR_SIZE);
        let ehdr: &ElfHeader = unsafe { &*(data.as_ptr().cast()) };
        ehdr.validate()?;
        Ok(ehdr)
    }

    /// Checks if the ELF file is a dynamic library (shared object)
    ///
    /// This method determines whether the ELF file is a shared object
    /// (dynamic library) that can be loaded and linked at runtime.
    ///
    /// # Returns
    /// * `true` - If the ELF file is a dynamic library (ET_DYN)
    /// * `false` - Otherwise
    #[inline]
    pub fn is_dylib(&self) -> bool {
        self.ehdr.e_type == ET_DYN
    }

    /// Checks if the ELF file is an executable
    ///
    /// This method determines whether the ELF file is an executable
    /// (either a standard executable or a position-independent executable).
    ///
    /// # Returns
    /// * `true` - If the ELF file is an executable (ET_EXEC or ET_DYN)
    /// * `false` - Otherwise
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.ehdr.e_type == ET_EXEC || self.ehdr.e_type == ET_DYN
    }

    /// Validates the ELF header
    ///
    /// This method performs several validation checks on the ELF header
    /// to ensure it is valid and compatible with the target architecture:
    /// 1. Checks the ELF magic bytes
    /// 2. Verifies the file class matches the target architecture
    /// 3. Ensures the ELF version is current
    /// 4. Confirms the machine architecture matches
    ///
    /// # Returns
    /// * `Ok(())` - If all validation checks pass
    /// * `Err(Error)` - If any validation check fails
    pub fn validate(&self) -> Result<()> {
        // Check ELF magic bytes
        if self.e_ident[0..4] != ELFMAGIC {
            return Err(parse_ehdr_error("invalid ELF magic"));
        }

        // Check file class (32-bit vs 64-bit)
        if self.e_ident[EI_CLASS] != E_CLASS {
            return Err(parse_ehdr_error("file class mismatch"));
        }

        // Check ELF version
        if self.e_ident[EI_VERSION] != EV_CURRENT {
            return Err(parse_ehdr_error("invalid ELF version"));
        }

        // Check machine architecture
        if self.e_machine != EM_ARCH {
            return Err(parse_ehdr_error("file arch mismatch"));
        }

        Ok(())
    }

    /// Gets the number of program headers
    ///
    /// # Returns
    /// The number of program header entries in the ELF file
    #[inline]
    pub fn e_phnum(&self) -> usize {
        self.ehdr.e_phnum as usize
    }

    /// Gets the size of each program header entry
    ///
    /// # Returns
    /// The size in bytes of each program header entry
    #[inline]
    pub fn e_phentsize(&self) -> usize {
        self.ehdr.e_phentsize as usize
    }

    /// Gets the file offset of the program header table
    ///
    /// # Returns
    /// The file offset in bytes where the program header table begins
    #[inline]
    pub fn e_phoff(&self) -> usize {
        self.ehdr.e_phoff as usize
    }

    /// Gets the file offset of the section header table
    ///
    /// # Returns
    /// The file offset in bytes where the section header table begins
    #[inline]
    pub fn e_shoff(&self) -> usize {
        self.ehdr.e_shoff as usize
    }

    /// Gets the size of each section header entry
    ///
    /// # Returns
    /// The size in bytes of each section header entry
    #[inline]
    pub fn e_shentsize(&self) -> usize {
        self.ehdr.e_shentsize as usize
    }

    /// Gets the number of section headers
    ///
    /// # Returns
    /// The number of section header entries in the ELF file
    #[inline]
    pub fn e_shnum(&self) -> usize {
        self.ehdr.e_shnum as usize
    }

    /// Calculates the byte range of the program header table
    ///
    /// This method calculates the start and end file offsets of the
    /// program header table based on the header information.
    ///
    /// # Returns
    /// A tuple containing:
    /// 1. The start offset of the program header table
    /// 2. The end offset of the program header table
    #[inline]
    pub fn phdr_range(&self) -> (usize, usize) {
        let phdrs_size = self.e_phentsize() * self.e_phnum();
        let phdr_start = self.e_phoff();
        let phdr_end = phdr_start + phdrs_size;
        (phdr_start, phdr_end)
    }

    /// Calculates the byte range of the section header table
    ///
    /// This method calculates the start and end file offsets of the
    /// section header table based on the header information.
    ///
    /// # Returns
    /// A tuple containing:
    /// 1. The start offset of the section header table
    /// 2. The end offset of the section header table
    #[inline]
    pub fn shdr_range(&self) -> (usize, usize) {
        let shdrs_size = self.e_shentsize() * self.e_shnum();
        let shdr_start = self.e_shoff();
        let shdr_end = shdr_start + shdrs_size;
        (shdr_start, shdr_end)
    }
}
