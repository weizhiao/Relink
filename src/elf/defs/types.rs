//! Semantic wrappers for ELF tag, type, flag, and index fields.

use bitflags::bitflags;
use core::fmt::{self, Display};
use elf::abi::*;

use crate::{arch::NativeArch, relocation::RelocationArch};

/// This element holds the total size, in bytes, of the DT_RELR relocation table.
pub const DT_RELRSZ: i64 = 35;
/// This element is similar to DT_RELA, except its table has implicit
/// addends and info, such as Elf32_Relr for the 32-bit file class or
/// Elf64_Relr for the 64-bit file class. If this element is present,
/// the dynamic structure must also have DT_RELRSZ and DT_RELRENT elements.
pub const DT_RELR: i64 = 36;
/// This element holds the size, in bytes, of the DT_RELR relocation entry.
pub const DT_RELRENT: i64 = 37;

/// Semantic wrapper for the ELF `d_tag` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfDynamicTag(i64);

impl ElfDynamicTag {
    pub const NULL: Self = Self(DT_NULL);
    pub const NEEDED: Self = Self(DT_NEEDED);
    pub const PLTRELSZ: Self = Self(DT_PLTRELSZ);
    pub const PLTGOT: Self = Self(DT_PLTGOT);
    pub const HASH: Self = Self(DT_HASH);
    pub const STRTAB: Self = Self(DT_STRTAB);
    pub const SYMTAB: Self = Self(DT_SYMTAB);
    pub const RELA: Self = Self(DT_RELA);
    pub const RELASZ: Self = Self(DT_RELASZ);
    pub const RELAENT: Self = Self(DT_RELAENT);
    pub const REL: Self = Self(DT_REL);
    pub const RELSZ: Self = Self(DT_RELSZ);
    pub const RELENT: Self = Self(DT_RELENT);
    pub const PLTREL: Self = Self(DT_PLTREL);
    pub const DEBUG: Self = Self(DT_DEBUG);
    pub const JMPREL: Self = Self(DT_JMPREL);
    pub const INIT: Self = Self(DT_INIT);
    pub const FINI: Self = Self(DT_FINI);
    pub const INIT_ARRAY: Self = Self(DT_INIT_ARRAY);
    pub const INIT_ARRAYSZ: Self = Self(DT_INIT_ARRAYSZ);
    pub const FINI_ARRAY: Self = Self(DT_FINI_ARRAY);
    pub const FINI_ARRAYSZ: Self = Self(DT_FINI_ARRAYSZ);
    pub const RPATH: Self = Self(DT_RPATH);
    pub const RUNPATH: Self = Self(DT_RUNPATH);
    pub const FLAGS: Self = Self(DT_FLAGS);
    pub const FLAGS_1: Self = Self(DT_FLAGS_1);
    pub const STRSZ: Self = Self(DT_STRSZ);
    pub const GNU_HASH: Self = Self(DT_GNU_HASH);
    pub const GNU_LIBLIST: Self = Self(DT_GNU_LIBLIST);
    pub const VERSYM: Self = Self(DT_VERSYM);
    pub const VERDEF: Self = Self(DT_VERDEF);
    pub const VERDEFNUM: Self = Self(DT_VERDEFNUM);
    pub const VERNEED: Self = Self(DT_VERNEED);
    pub const VERNEEDNUM: Self = Self(DT_VERNEEDNUM);
    pub const RELACOUNT: Self = Self(DT_RELACOUNT);
    pub const RELCOUNT: Self = Self(DT_RELCOUNT);
    pub const RELR: Self = Self(DT_RELR);
    pub const RELRSZ: Self = Self(DT_RELRSZ);
    pub const RELRENT: Self = Self(DT_RELRENT);

    #[inline]
    pub const fn new(raw: i64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }
}

impl From<i64> for ElfDynamicTag {
    #[inline]
    fn from(value: i64) -> Self {
        Self::new(value)
    }
}

impl From<ElfDynamicTag> for i64 {
    #[inline]
    fn from(value: ElfDynamicTag) -> Self {
        value.raw()
    }
}

impl Display for ElfDynamicTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            DT_NULL => f.write_str("DT_NULL"),
            DT_NEEDED => f.write_str("DT_NEEDED"),
            DT_PLTRELSZ => f.write_str("DT_PLTRELSZ"),
            DT_PLTGOT => f.write_str("DT_PLTGOT"),
            DT_HASH => f.write_str("DT_HASH"),
            DT_STRTAB => f.write_str("DT_STRTAB"),
            DT_SYMTAB => f.write_str("DT_SYMTAB"),
            DT_RELA => f.write_str("DT_RELA"),
            DT_RELASZ => f.write_str("DT_RELASZ"),
            DT_REL => f.write_str("DT_REL"),
            DT_RELSZ => f.write_str("DT_RELSZ"),
            DT_PLTREL => f.write_str("DT_PLTREL"),
            elf::abi::DT_DEBUG => f.write_str("DT_DEBUG"),
            DT_JMPREL => f.write_str("DT_JMPREL"),
            DT_INIT => f.write_str("DT_INIT"),
            DT_FINI => f.write_str("DT_FINI"),
            DT_INIT_ARRAY => f.write_str("DT_INIT_ARRAY"),
            DT_INIT_ARRAYSZ => f.write_str("DT_INIT_ARRAYSZ"),
            DT_FINI_ARRAY => f.write_str("DT_FINI_ARRAY"),
            DT_FINI_ARRAYSZ => f.write_str("DT_FINI_ARRAYSZ"),
            DT_RPATH => f.write_str("DT_RPATH"),
            DT_RUNPATH => f.write_str("DT_RUNPATH"),
            DT_FLAGS => f.write_str("DT_FLAGS"),
            DT_FLAGS_1 => f.write_str("DT_FLAGS_1"),
            DT_GNU_HASH => f.write_str("DT_GNU_HASH"),
            DT_GNU_LIBLIST => f.write_str("DT_GNU_LIBLIST"),
            DT_VERSYM => f.write_str("DT_VERSYM"),
            DT_VERDEF => f.write_str("DT_VERDEF"),
            DT_VERDEFNUM => f.write_str("DT_VERDEFNUM"),
            DT_VERNEED => f.write_str("DT_VERNEED"),
            DT_VERNEEDNUM => f.write_str("DT_VERNEEDNUM"),
            DT_RELACOUNT => f.write_str("DT_RELACOUNT"),
            DT_RELCOUNT => f.write_str("DT_RELCOUNT"),
            DT_RELR => f.write_str("DT_RELR"),
            DT_RELRSZ => f.write_str("DT_RELRSZ"),
            raw => write!(f, "unknown ELF dynamic tag {raw}"),
        }
    }
}

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

/// Semantic wrapper for the ELF `sh_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfSectionType(u32);

impl ElfSectionType {
    pub const NULL: Self = Self(SHT_NULL);
    pub const PROGBITS: Self = Self(SHT_PROGBITS);
    pub const SYMTAB: Self = Self(SHT_SYMTAB);
    pub const STRTAB: Self = Self(SHT_STRTAB);
    pub const RELA: Self = Self(SHT_RELA);
    pub const HASH: Self = Self(SHT_HASH);
    pub const DYNAMIC: Self = Self(SHT_DYNAMIC);
    pub const NOTE: Self = Self(SHT_NOTE);
    pub const NOBITS: Self = Self(SHT_NOBITS);
    pub const REL: Self = Self(SHT_REL);
    pub const SHLIB: Self = Self(SHT_SHLIB);
    pub const DYNSYM: Self = Self(SHT_DYNSYM);
    pub const INIT_ARRAY: Self = Self(SHT_INIT_ARRAY);
    pub const FINI_ARRAY: Self = Self(SHT_FINI_ARRAY);
    pub const PREINIT_ARRAY: Self = Self(SHT_PREINIT_ARRAY);
    pub const GROUP: Self = Self(SHT_GROUP);
    pub const SYMTAB_SHNDX: Self = Self(SHT_SYMTAB_SHNDX);

    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for ElfSectionType {
    #[inline]
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<ElfSectionType> for u32 {
    #[inline]
    fn from(value: ElfSectionType) -> Self {
        value.raw()
    }
}

impl Display for ElfSectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SHT_NULL => f.write_str("SHT_NULL"),
            SHT_PROGBITS => f.write_str("SHT_PROGBITS"),
            SHT_SYMTAB => f.write_str("SHT_SYMTAB"),
            SHT_STRTAB => f.write_str("SHT_STRTAB"),
            SHT_RELA => f.write_str("SHT_RELA"),
            SHT_HASH => f.write_str("SHT_HASH"),
            SHT_DYNAMIC => f.write_str("SHT_DYNAMIC"),
            SHT_NOTE => f.write_str("SHT_NOTE"),
            SHT_NOBITS => f.write_str("SHT_NOBITS"),
            SHT_REL => f.write_str("SHT_REL"),
            SHT_SHLIB => f.write_str("SHT_SHLIB"),
            SHT_DYNSYM => f.write_str("SHT_DYNSYM"),
            SHT_INIT_ARRAY => f.write_str("SHT_INIT_ARRAY"),
            SHT_FINI_ARRAY => f.write_str("SHT_FINI_ARRAY"),
            SHT_PREINIT_ARRAY => f.write_str("SHT_PREINIT_ARRAY"),
            SHT_GROUP => f.write_str("SHT_GROUP"),
            SHT_SYMTAB_SHNDX => f.write_str("SHT_SYMTAB_SHNDX"),
            raw => write!(f, "unknown ELF section type {raw}"),
        }
    }
}

bitflags! {
    /// Bitflags wrapper for the ELF `sh_flags` field.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ElfSectionFlags: u64 {
        const WRITE = SHF_WRITE as u64;
        const ALLOC = SHF_ALLOC as u64;
        const EXECINSTR = SHF_EXECINSTR as u64;
        const TLS = SHF_TLS as u64;
    }
}

/// Semantic wrapper for the ELF symbol binding field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfSymbolBind(u8);

impl ElfSymbolBind {
    pub const LOCAL: Self = Self(STB_LOCAL);
    pub const GLOBAL: Self = Self(STB_GLOBAL);
    pub const WEAK: Self = Self(STB_WEAK);
    pub const GNU_UNIQUE: Self = Self(STB_GNU_UNIQUE);

    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }
}

impl From<u8> for ElfSymbolBind {
    #[inline]
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<ElfSymbolBind> for u8 {
    #[inline]
    fn from(value: ElfSymbolBind) -> Self {
        value.raw()
    }
}

impl Display for ElfSymbolBind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            STB_LOCAL => f.write_str("STB_LOCAL"),
            STB_GLOBAL => f.write_str("STB_GLOBAL"),
            STB_WEAK => f.write_str("STB_WEAK"),
            STB_GNU_UNIQUE => f.write_str("STB_GNU_UNIQUE"),
            raw => write!(f, "unknown ELF symbol bind {raw}"),
        }
    }
}

/// Semantic wrapper for the ELF symbol type field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfSymbolType(u8);

impl ElfSymbolType {
    pub const NOTYPE: Self = Self(STT_NOTYPE);
    pub const OBJECT: Self = Self(STT_OBJECT);
    pub const FUNC: Self = Self(STT_FUNC);
    pub const SECTION: Self = Self(STT_SECTION);
    pub const FILE: Self = Self(STT_FILE);
    pub const COMMON: Self = Self(STT_COMMON);
    pub const TLS: Self = Self(STT_TLS);
    pub const GNU_IFUNC: Self = Self(STT_GNU_IFUNC);

    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }
}

impl From<u8> for ElfSymbolType {
    #[inline]
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<ElfSymbolType> for u8 {
    #[inline]
    fn from(value: ElfSymbolType) -> Self {
        value.raw()
    }
}

impl Display for ElfSymbolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            STT_NOTYPE => f.write_str("STT_NOTYPE"),
            STT_OBJECT => f.write_str("STT_OBJECT"),
            STT_FUNC => f.write_str("STT_FUNC"),
            STT_SECTION => f.write_str("STT_SECTION"),
            STT_FILE => f.write_str("STT_FILE"),
            STT_COMMON => f.write_str("STT_COMMON"),
            STT_TLS => f.write_str("STT_TLS"),
            STT_GNU_IFUNC => f.write_str("STT_GNU_IFUNC"),
            raw => write!(f, "unknown ELF symbol type {raw}"),
        }
    }
}

/// Semantic wrapper for the ELF symbol `st_shndx` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfSectionIndex(u16);

impl ElfSectionIndex {
    pub const UNDEF: Self = Self(SHN_UNDEF);
    pub const ABS: Self = Self(SHN_ABS);
    pub const COMMON: Self = Self(SHN_COMMON);
    pub const XINDEX: Self = Self(SHN_XINDEX);

    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }

    #[inline]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    #[inline]
    pub const fn is_undef(self) -> bool {
        self.0 == SHN_UNDEF
    }

    #[inline]
    pub const fn is_abs(self) -> bool {
        self.0 == SHN_ABS
    }
}

impl Display for ElfSectionIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SHN_UNDEF => f.write_str("SHN_UNDEF"),
            SHN_ABS => f.write_str("SHN_ABS"),
            SHN_COMMON => f.write_str("SHN_COMMON"),
            SHN_XINDEX => f.write_str("SHN_XINDEX"),
            raw => write!(f, "ELF symbol section index {raw}"),
        }
    }
}

/// Semantic wrapper for the ELF `EI_CLASS` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfClass(u8);

impl ElfClass {
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
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
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

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

/// Semantic wrapper for the ELF `e_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfFileType(u16);

impl ElfFileType {
    pub const NONE: Self = Self(ET_NONE);
    pub const REL: Self = Self(ET_REL);
    pub const EXEC: Self = Self(ET_EXEC);
    pub const DYN: Self = Self(ET_DYN);
    pub const CORE: Self = Self(ET_CORE);

    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

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

/// Semantic wrapper for the ELF relocation type encoded in `r_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfRelocationType(u32);

impl ElfRelocationType {
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for ElfRelocationType {
    #[inline]
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<ElfRelocationType> for u32 {
    #[inline]
    fn from(value: ElfRelocationType) -> Self {
        value.raw()
    }
}

impl Display for ElfRelocationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<NativeArch as RelocationArch>::rel_type_to_str(*self))
    }
}
