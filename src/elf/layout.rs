//! ELF class and byte-order layout selection.

use super::raw::{
    Elf32Sym, ElfDynRaw, ElfEhdrRaw, ElfPhdrRaw, ElfRelRaw, ElfRelaRaw, ElfShdrRaw, ElfSymRaw,
    ElfWord,
};
use core::fmt::{self, Display};
use elf::abi::{ELFDATA2LSB, ELFDATA2MSB, ELFDATANONE};

/// Semantic wrapper for the ELF `EI_DATA` byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfDataEncoding(u8);

impl ElfDataEncoding {
    /// `ELFDATANONE`: invalid data encoding.
    pub const NONE: Self = Self(ELFDATANONE);
    /// `ELFDATA2LSB`: little-endian two's-complement data.
    pub const LSB: Self = Self(ELFDATA2LSB);
    /// `ELFDATA2MSB`: big-endian two's-complement data.
    pub const MSB: Self = Self(ELFDATA2MSB);

    /// Creates an ELF data encoding wrapper from a raw `EI_DATA` byte.
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the raw `EI_DATA` byte.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }
}

impl From<u8> for ElfDataEncoding {
    #[inline]
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<ElfDataEncoding> for u8 {
    #[inline]
    fn from(value: ElfDataEncoding) -> Self {
        value.raw()
    }
}

impl Display for ElfDataEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ELFDATANONE => f.write_str("ELFDATANONE"),
            ELFDATA2LSB => f.write_str("ELFDATA2LSB"),
            ELFDATA2MSB => f.write_str("ELFDATA2MSB"),
            raw => write!(f, "unknown ELF data encoding {raw}"),
        }
    }
}

/// Groups the raw ELF types/constants selected for one ELF class.
pub trait ElfLayout: 'static {
    /// ELF class value (`ELFCLASS32` or `ELFCLASS64`).
    const E_CLASS: u8;
    /// ELF data encoding expected by this layout's raw field accessors.
    const DATA_ENCODING: ElfDataEncoding = if cfg!(target_endian = "little") {
        ElfDataEncoding::LSB
    } else {
        ElfDataEncoding::MSB
    };
    /// Bit mask used to extract relocation type bits from `r_info`.
    const REL_MASK: usize;
    /// Bit shift used to extract relocation symbol bits from `r_info`.
    const REL_BIT: usize;
    /// Size of this layout's ELF header.
    const EHDR_SIZE: usize;

    /// Raw program-header type for this class.
    type Phdr: ElfPhdrRaw;
    /// Raw section-header type for this class.
    type Shdr: ElfShdrRaw;
    /// Raw dynamic-entry type for this class.
    type Dyn: ElfDynRaw;
    /// Raw ELF-header type for this class.
    type Ehdr: ElfEhdrRaw;
    /// Raw explicit-addend relocation type for this class.
    type Rela: ElfRelaRaw;
    /// Raw implicit-addend relocation type for this class.
    type Rel: ElfRelRaw;
    /// Raw compact RELR relocation word for this class.
    type Relr: ElfWord;
    /// Native ELF word type for this class.
    type Word: ElfWord;
    /// Raw symbol-table entry type for this class.
    type Sym: ElfSymRaw;
}

/// Marker for 32-bit ELF class layouts.
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

/// Marker for 64-bit ELF class layouts.
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
/// ELF layout matching the host pointer width.
pub type NativeElfLayout = Elf64Layout;
#[cfg(not(target_pointer_width = "64"))]
/// ELF layout matching the host pointer width.
pub type NativeElfLayout = Elf32Layout;

pub(crate) type ElfEhdr = <NativeElfLayout as ElfLayout>::Ehdr;
