//! ELF header parsing and validation
//!
//! This module provides functionality for parsing and validating ELF headers,
//! which contain essential metadata about ELF files such as architecture,
//! file type, and section/program header information.

use crate::{
    ParseEhdrError, ParsePhdrError, Result,
    elf::{
        ElfClass, ElfEhdrRaw, ElfFileType, ElfLayout, ElfMachine, ElfPhdr, ElfShdr, NativeElfLayout,
    },
};
use core::mem::size_of;
use elf::abi::{EI_CLASS, EI_VERSION, ELFMAGIC, EV_CURRENT};

/// A wrapper around the ELF header structure
///
/// This structure provides safe access to ELF header data with validation
/// to ensure the ELF file is compatible with the target architecture
/// and follows the expected format.
#[repr(transparent)]
pub struct ElfHeader<L: ElfLayout = NativeElfLayout> {
    /// The underlying ELF header structure
    ehdr: L::Ehdr,
}

impl<L: ElfLayout> ElfHeader<L> {
    /// Wraps a raw header and validates it.
    ///
    /// When `expected_machine` is `Some(value)`, validation requires
    /// `e_machine == value`. When it is `None`, the machine architecture
    /// check is skipped, enabling cross-architecture loading (for example
    /// mapping an x86-64 ELF on a RISC-V host). All other validations
    /// (magic, class, version) always run.
    #[inline]
    pub(crate) fn from_raw(ehdr: L::Ehdr, expected_machine: Option<ElfMachine>) -> Result<Self> {
        let ehdr = Self { ehdr };
        ehdr.validate(expected_machine)?;
        Ok(ehdr)
    }

    /// Returns `true` if the ELF file is a dynamic library (shared object).
    #[inline]
    pub fn is_dylib(&self) -> bool {
        self.file_type() == ElfFileType::DYN
    }

    /// Returns `true` if the ELF file is an executable.
    #[inline]
    pub fn is_executable(&self) -> bool {
        let file_type = self.file_type();
        file_type == ElfFileType::EXEC || file_type == ElfFileType::DYN
    }

    /// Returns the parsed ELF class of this header.
    #[inline]
    pub fn class(&self) -> ElfClass {
        ElfClass::new(self.ehdr.e_ident()[EI_CLASS])
    }

    /// Returns the parsed ELF machine type of this header.
    #[inline]
    pub fn machine(&self) -> ElfMachine {
        ElfMachine::new(self.ehdr.e_machine())
    }

    /// Returns the parsed ELF file type of this header.
    #[inline]
    pub fn file_type(&self) -> ElfFileType {
        ElfFileType::new(self.ehdr.e_type())
    }

    /// Returns the entry-point virtual address (`e_entry`) as a native-sized value.
    #[inline]
    pub fn e_entry(&self) -> usize {
        self.ehdr.e_entry()
    }

    /// Validates the ELF header magic, class, version, and optionally architecture.
    ///
    /// When `expected_machine` is `None`, the machine architecture check is
    /// skipped. This is intended for cross-architecture loaders that map ELF
    /// files targeting a different CPU than the host. When `Some(value)`,
    /// the header's `e_machine` must equal `value`.
    pub(crate) fn validate(&self, expected_machine: Option<ElfMachine>) -> Result<()> {
        // Check ELF magic bytes
        if self.ehdr.e_ident()[0..4] != ELFMAGIC {
            return Err(ParseEhdrError::InvalidMagic.into());
        }

        // Check file class (32-bit vs 64-bit)
        let class = self.class();
        if class.raw() != L::E_CLASS {
            return Err(ParseEhdrError::FileClassMismatch {
                expected: ElfClass::new(L::E_CLASS),
                found: class,
            }
            .into());
        }

        // Check ELF version
        if self.ehdr.e_ident()[EI_VERSION] != EV_CURRENT {
            return Err(ParseEhdrError::InvalidVersion.into());
        }

        if let Some(expected) = expected_machine {
            // Check machine architecture against the caller-supplied target.
            let machine = self.machine();
            if machine != expected {
                return Err(ParseEhdrError::FileArchMismatch {
                    expected,
                    found: machine,
                }
                .into());
            }
        }

        Ok(())
    }

    /// Returns the number of program headers.
    #[inline]
    pub fn e_phnum(&self) -> usize {
        self.ehdr.e_phnum()
    }

    /// Returns the size of each program header entry.
    #[inline]
    pub fn e_phentsize(&self) -> usize {
        self.ehdr.e_phentsize()
    }

    /// Returns the file offset of the program header table.
    #[inline]
    pub fn e_phoff(&self) -> usize {
        self.ehdr.e_phoff()
    }

    /// Returns the file offset of the section header table.
    #[inline]
    pub fn e_shoff(&self) -> usize {
        self.ehdr.e_shoff()
    }

    /// Returns the size of each section header entry.
    #[inline]
    pub fn e_shentsize(&self) -> usize {
        self.ehdr.e_shentsize()
    }

    /// Returns the number of section headers.
    #[inline]
    pub fn e_shnum(&self) -> usize {
        self.ehdr.e_shnum()
    }

    /// Returns the section-name string-table index.
    #[inline]
    pub fn e_shstrndx(&self) -> usize {
        self.ehdr.e_shstrndx()
    }

    /// Returns the `(start, end)` file offsets of the program header table.
    #[inline]
    pub fn phdr_range(&self) -> (usize, usize) {
        table_range(self.e_phoff(), self.e_phentsize(), self.e_phnum())
    }

    /// Returns the checked `(start, size)` layout for the program header table.
    ///
    /// This validates entry-size compatibility and overflow-prone arithmetic.
    #[inline]
    pub(crate) fn checked_phdr_layout(&self) -> Result<Option<(usize, usize)>> {
        checked_table_layout(
            self.e_phentsize(),
            size_of::<ElfPhdr<L>>(),
            self.e_phnum(),
            self.e_phoff(),
            || ParsePhdrError::MalformedProgramHeaders.into(),
        )
    }

    /// Returns the `(start, end)` file offsets of the section header table.
    #[inline]
    pub fn shdr_range(&self) -> (usize, usize) {
        table_range(self.e_shoff(), self.e_shentsize(), self.e_shnum())
    }

    /// Returns the checked `(start, size)` layout for the section header table.
    ///
    /// This validates entry-size compatibility and overflow-prone arithmetic.
    #[inline]
    #[cfg_attr(not(feature = "object"), allow(dead_code))]
    pub(crate) fn checked_shdr_layout(&self) -> Result<Option<(usize, usize)>> {
        checked_table_layout(
            self.e_shentsize(),
            size_of::<ElfShdr<L>>(),
            self.e_shnum(),
            self.e_shoff(),
            || ParseEhdrError::MissingSectionHeaders.into(),
        )
    }
}

#[inline]
const fn table_range(offset: usize, entsize: usize, count: usize) -> (usize, usize) {
    let size = entsize * count;
    (offset, offset + size)
}

#[inline]
fn checked_table_layout(
    entsize: usize,
    expected_entsize: usize,
    count: usize,
    offset: usize,
    err: impl Fn() -> crate::Error,
) -> Result<Option<(usize, usize)>> {
    if entsize != expected_entsize {
        return Err(err());
    }

    let size = entsize.checked_mul(count).ok_or_else(&err)?;
    if size == 0 {
        return Ok(None);
    }

    offset.checked_add(size).ok_or_else(err)?;
    Ok(Some((offset, size)))
}
