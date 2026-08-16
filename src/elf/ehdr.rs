//! ELF header parsing and validation
//!
//! This module provides functionality for parsing and validating ELF headers,
//! which contain essential metadata about ELF files such as architecture,
//! file type, and section/program header information.

use super::raw::ElfEhdrRaw;
use crate::{
    IoError, ParseEhdrError, ParsePhdrError, ParseShdrError, ReadBoundsError, Result,
    elf::{ElfDataEncoding, ElfLayout, ElfPhdr, ElfShdr, NativeElfLayout},
    input::ElfReader,
};
use alloc::boxed::Box;
use core::{
    fmt::{self, Display},
    mem::size_of,
};
use elf::abi::*;

/// Semantic wrapper for the ELF `EI_CLASS` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfClass(u8);

impl ElfClass {
    /// 32-bit ELF layout.
    pub const ELF32: Self = Self(ELFCLASS32);
    /// 64-bit ELF layout.
    pub const ELF64: Self = Self(ELFCLASS64);

    /// Creates an ELF class wrapper from a raw `EI_CLASS` value.
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the raw `EI_CLASS` value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Returns whether this is the 64-bit ELF class.
    #[inline]
    pub const fn is_64(self) -> bool {
        matches!(self, Self::ELF64)
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
    /// Creates a machine wrapper from a raw `e_machine` value.
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the raw `e_machine` value.
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

/// Architecture-relevant fields shared by every ELF header layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElfTarget {
    class: ElfClass,
    encoding: ElfDataEncoding,
    machine: ElfMachine,
}

impl ElfTarget {
    /// Creates an ELF target description.
    #[inline]
    pub const fn new(class: ElfClass, encoding: ElfDataEncoding, machine: ElfMachine) -> Self {
        Self {
            class,
            encoding,
            machine,
        }
    }

    /// Parses the architecture fields from an ELF header prefix.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 20 {
            return Err(IoError::ReadOutOfBounds(Box::new(ReadBoundsError::new(
                0,
                20,
                bytes.len(),
            )))
            .into());
        }
        if !bytes.starts_with(&ELFMAGIC) {
            return Err(ParseEhdrError::InvalidMagic.into());
        }

        let class = ElfClass::new(bytes[EI_CLASS]);
        if !matches!(class, ElfClass::ELF32 | ElfClass::ELF64) {
            return Err(ParseEhdrError::InvalidClass { found: class }.into());
        }

        let encoding = ElfDataEncoding::new(bytes[EI_DATA]);
        let machine = match encoding {
            ElfDataEncoding::LSB => u16::from_le_bytes([bytes[18], bytes[19]]),
            ElfDataEncoding::MSB => u16::from_be_bytes([bytes[18], bytes[19]]),
            _ => {
                return Err(ParseEhdrError::InvalidDataEncoding { found: encoding }.into());
            }
        };
        if bytes[EI_VERSION] != EV_CURRENT {
            return Err(ParseEhdrError::InvalidVersion.into());
        }
        Ok(Self::new(class, encoding, ElfMachine::new(machine)))
    }

    /// Reads and parses the architecture fields from an ELF source.
    pub fn read(reader: &(impl ElfReader + ?Sized)) -> Result<Self> {
        let mut header = [0; 20];
        reader.read(&mut header, 0)?;
        Self::from_bytes(&header)
    }

    /// Returns the ELF class used by this target.
    #[inline]
    pub const fn class(self) -> ElfClass {
        self.class
    }

    /// Returns the ELF byte order used by this target.
    #[inline]
    pub const fn encoding(self) -> ElfDataEncoding {
        self.encoding
    }

    /// Returns the ELF machine used by this target.
    #[inline]
    pub const fn machine(self) -> ElfMachine {
        self.machine
    }

    fn ensure_matches(self, expected: Self) -> Result<()> {
        if self.class != expected.class {
            return Err(ParseEhdrError::FileClassMismatch {
                expected: expected.class,
                found: self.class,
            }
            .into());
        }
        if self.encoding != expected.encoding {
            return Err(ParseEhdrError::FileEndianMismatch {
                expected: expected.encoding,
                found: self.encoding,
            }
            .into());
        }
        if self.machine != expected.machine {
            return Err(ParseEhdrError::FileArchMismatch {
                expected: expected.machine,
                found: self.machine,
            }
            .into());
        }
        Ok(())
    }
}

/// Semantic wrapper for the ELF `e_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfFileType(u16);

impl ElfFileType {
    /// `ET_NONE`: no file type.
    pub const NONE: Self = Self(ET_NONE);
    /// `ET_REL`: relocatable object file.
    pub const REL: Self = Self(ET_REL);
    /// `ET_EXEC`: executable file.
    pub const EXEC: Self = Self(ET_EXEC);
    /// `ET_DYN`: shared object or PIE-style image.
    pub const DYN: Self = Self(ET_DYN);
    /// `ET_CORE`: core dump file.
    pub const CORE: Self = Self(ET_CORE);

    /// Creates a file type wrapper from a raw `e_type` value.
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the raw `e_type` value.
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
    /// `expected` describes the class, byte order, and machine required by the
    /// selected relocation architecture.
    #[inline]
    pub(crate) fn from_raw(ehdr: L::Ehdr, expected: ElfTarget) -> Result<Self> {
        let ehdr = Self { ehdr };
        ehdr.validate(expected)?;
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

    /// Returns the parsed ELF data encoding (`EI_DATA`) byte.
    #[inline]
    pub fn data_encoding(&self) -> ElfDataEncoding {
        ElfDataEncoding::new(self.ehdr.e_ident()[EI_DATA])
    }

    /// Returns the parsed ELF machine type of this header.
    #[inline]
    pub fn machine(&self) -> ElfMachine {
        ElfMachine::new(self.ehdr.e_machine())
    }

    /// Returns the architecture-relevant fields of this header.
    #[inline]
    pub fn target(&self) -> ElfTarget {
        ElfTarget::new(self.class(), self.data_encoding(), self.machine())
    }

    /// Returns the processor-specific ELF header flags (`e_flags`).
    #[inline]
    pub fn e_flags(&self) -> u32 {
        self.ehdr.e_flags()
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

    /// Validates the ELF header and its target against `expected`.
    pub(crate) fn validate(&self, expected: ElfTarget) -> Result<()> {
        // Check ELF magic bytes
        if self.ehdr.e_ident()[0..4] != ELFMAGIC {
            return Err(ParseEhdrError::InvalidMagic.into());
        }

        self.target().ensure_matches(expected)?;

        // Check ELF version
        if self.ehdr.e_ident()[EI_VERSION] != EV_CURRENT {
            return Err(ParseEhdrError::InvalidVersion.into());
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
    pub fn phdr_range(&self) -> Result<Option<(usize, usize)>> {
        checked_table_range(self.e_phentsize(), self.e_phnum(), self.e_phoff())
    }

    /// Returns the checked `(start, size)` layout for the program header table.
    ///
    /// This validates entry-size compatibility, overflow-prone arithmetic, and
    /// that the table stays within the object length.
    #[inline]
    pub(crate) fn checked_phdr_layout(&self, object_len: usize) -> Result<Option<(usize, usize)>> {
        if self.e_phentsize() != size_of::<ElfPhdr<L>>() {
            return Err(ParsePhdrError::InvalidEntrySize {
                expected: size_of::<ElfPhdr<L>>(),
                found: self.e_phentsize(),
            }
            .into());
        }

        checked_table_layout(
            self.e_phentsize(),
            self.e_phnum(),
            self.e_phoff(),
            object_len,
        )
    }

    /// Returns the `(start, end)` file offsets of the section header table.
    #[inline]
    pub fn shdr_range(&self) -> Result<Option<(usize, usize)>> {
        checked_table_range(self.e_shentsize(), self.e_shnum(), self.e_shoff())
    }

    /// Returns the checked `(start, size)` layout for the section header table.
    ///
    /// This validates entry-size compatibility, overflow-prone arithmetic, and
    /// that the table stays within the object length.
    #[inline]
    pub(crate) fn checked_shdr_layout(&self, object_len: usize) -> Result<Option<(usize, usize)>> {
        if self.e_shentsize() != size_of::<ElfShdr<L>>() {
            return Err(ParseShdrError::InvalidEntrySize {
                expected: size_of::<ElfShdr<L>>(),
                found: self.e_shentsize(),
            }
            .into());
        }

        checked_table_layout(
            self.e_shentsize(),
            self.e_shnum(),
            self.e_shoff(),
            object_len,
        )
    }
}

#[inline]
fn checked_table_layout(
    entsize: usize,
    count: usize,
    offset: usize,
    object_len: usize,
) -> Result<Option<(usize, usize)>> {
    let Some((offset, end)) = checked_table_range(entsize, count, offset)? else {
        return Ok(None);
    };
    let size = end - offset;

    if end > object_len {
        return Err(IoError::ReadOutOfBounds(Box::new(ReadBoundsError::new(
            offset, size, object_len,
        )))
        .into());
    }

    Ok(Some((offset, size)))
}

#[inline]
fn checked_table_range(
    entsize: usize,
    count: usize,
    offset: usize,
) -> Result<Option<(usize, usize)>> {
    let size = entsize
        .checked_mul(count)
        .ok_or(IoError::ReadBufferTooLarge)?;
    if size == 0 {
        return Ok(None);
    }

    let end = offset
        .checked_add(size)
        .ok_or(IoError::ReadBufferTooLarge)?;
    Ok(Some((offset, end)))
}
