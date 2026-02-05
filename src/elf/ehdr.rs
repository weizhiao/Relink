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
use alloc::format;
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
    /// Creates a new `ElfHeader` from raw data, validating it for the target architecture.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is too short or doesn't represent a valid ELF header.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `data` contains at least `EHDR_SIZE` bytes.
    pub(crate) fn new(data: &[u8]) -> Result<&Self> {
        debug_assert!(data.len() >= EHDR_SIZE);
        let ehdr: &ElfHeader = unsafe { &*(data.as_ptr().cast()) };
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

    /// Validates the ELF header magic, class, version, and architecture.
    pub fn validate(&self) -> Result<()> {
        // Check ELF magic bytes
        if self.e_ident[0..4] != ELFMAGIC {
            return Err(parse_ehdr_error("invalid ELF magic"));
        }

        // Check file class (32-bit vs 64-bit)
        if self.e_ident[EI_CLASS] != E_CLASS {
            return Err(parse_ehdr_error(format!(
                "file class mismatch: expected {}, found {}",
                E_CLASS, self.e_ident[EI_CLASS]
            )));
        }

        // Check ELF version
        if self.e_ident[EI_VERSION] != EV_CURRENT {
            return Err(parse_ehdr_error("invalid ELF version"));
        }

        // Check machine architecture
        if self.e_machine != EM_ARCH {
            return Err(parse_ehdr_error(format!(
                "file arch mismatch: expected {}, found {}",
                machine_to_str(EM_ARCH),
                machine_to_str(self.e_machine),
            )));
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

    /// Returns the `(start, end)` file offsets of the section header table.
    #[inline]
    pub fn shdr_range(&self) -> (usize, usize) {
        let shdrs_size = self.e_shentsize() * self.e_shnum();
        let shdr_start = self.e_shoff();
        let shdr_end = shdr_start + shdrs_size;
        (shdr_start, shdr_end)
    }
}

fn machine_to_str(machine: u16) -> &'static str {
    match machine {
        elf::abi::EM_X86_64 => "x86_64",
        elf::abi::EM_AARCH64 => "AArch64",
        elf::abi::EM_RISCV => "RISC-V",
        elf::abi::EM_386 => "x86",
        elf::abi::EM_ARM => "ARM",
        258 => "LoongArch",
        _ => "unknown",
    }
}
