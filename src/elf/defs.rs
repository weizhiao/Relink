//! ELF format definitions and utilities.
//!
//! This module provides core ELF (Executable and Linkable Format) data structures
//! and helper functions for parsing and manipulating ELF files. It includes
//! definitions for relocation entries, symbols, program headers, and section headers,
//! with support for both 32-bit and 64-bit ELF formats.

use core::{
    fmt::{self, Display},
    ops::{Deref, DerefMut},
};
use elf::abi::{
    ELFCLASS32, ELFCLASS64, ELFCLASSNONE, EM_386, EM_AARCH64, EM_ARM, EM_RISCV, EM_X86_64, ET_CORE,
    ET_DYN, ET_EXEC, ET_NONE, ET_REL, SHN_UNDEF, STB_GLOBAL, STB_GNU_UNIQUE, STB_LOCAL, STB_WEAK,
    STT_COMMON, STT_FUNC, STT_GNU_IFUNC, STT_NOTYPE, STT_OBJECT, STT_TLS,
};
#[cfg(all(feature = "object", any(target_arch = "x86", target_arch = "arm")))]
use elf::abi::SHT_REL;
#[cfg(all(feature = "object", not(any(target_arch = "x86", target_arch = "arm"))))]
use elf::abi::SHT_RELA;

use crate::arch::rel_type_to_str;

/// Valid symbol binding types bitmask.
/// This mask includes STB_GLOBAL, STB_WEAK, and STB_GNU_UNIQUE bindings.
const OK_BINDS: usize = 1 << STB_GLOBAL | 1 << STB_WEAK | 1 << STB_GNU_UNIQUE;

/// Valid symbol type bitmask.
/// This mask includes STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_COMMON, STT_TLS, and STT_GNU_IFUNC types.
const OK_TYPES: usize = 1 << STT_NOTYPE
    | 1 << STT_OBJECT
    | 1 << STT_FUNC
    | 1 << STT_COMMON
    | 1 << STT_TLS
    | 1 << STT_GNU_IFUNC;

cfg_if::cfg_if! {
    if #[cfg(target_pointer_width = "64")]{
        pub(crate) const E_CLASS: u8 = elf::abi::ELFCLASS64;
        pub(crate) type Phdr = elf::segment::Elf64_Phdr;
        pub(crate) type Shdr = elf::section::Elf64_Shdr;
        /// ELF dynamic section entry.
        pub type ElfDyn = elf::dynamic::Elf64_Dyn;
        pub(crate) type ElfEhdr = elf::file::Elf64_Ehdr;
        pub(crate) type Rela = elf::relocation::Elf64_Rela;
        pub(crate) type Rel = elf::relocation::Elf64_Rel;
        pub(crate) type Relr = u64;
        pub(crate) type Sym = elf::symbol::Elf64_Sym;
        pub(crate) const REL_MASK: usize = 0xFFFFFFFF;
        pub(crate) const REL_BIT: usize = 32;
        pub(crate) const EHDR_SIZE: usize = core::mem::size_of::<elf::file::Elf64_Ehdr>();
    }else{
        pub(crate) const E_CLASS: u8 = elf::abi::ELFCLASS32;
        pub(crate) type Phdr = elf::segment::Elf32_Phdr;
        pub(crate) type Shdr = elf::section::Elf32_Shdr;
        /// ELF dynamic section entry.
        pub type ElfDyn = elf::dynamic::Elf32_Dyn;
        pub(crate) type ElfEhdr = elf::file::Elf32_Ehdr;
        pub(crate) type Rela = elf::relocation::Elf32_Rela;
        pub(crate) type Rel = elf::relocation::Elf32_Rel;
        pub(crate) type Relr = u32;
        pub(crate) type Sym = Elf32Sym;
        pub(crate) const REL_MASK: usize = 0xFF;
        pub(crate) const REL_BIT: usize = 8;
        pub(crate) const EHDR_SIZE: usize = core::mem::size_of::<elf::file::Elf32_Ehdr>();
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

#[allow(unused)]
#[repr(C)]
/// 32-bit ELF symbol table entry.
/// This struct represents the native 32-bit symbol format used in ELF32 files.
/// For 64-bit targets, the `Sym` type alias points to `elf::symbol::Elf64_Sym` instead.
struct Elf32Sym {
    pub st_name: u32,
    pub st_value: u32,
    pub st_size: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
}

/// This element holds the total size, in bytes, of the DT_RELR relocation table.
pub const DT_RELRSZ: i64 = 35;
/// This element is similar to DT_RELA, except its table has implicit
/// addends and info, such as Elf32_Relr for the 32-bit file class or
/// Elf64_Relr for the 64-bit file class. If this element is present,
/// the dynamic structure must also have DT_RELRSZ and DT_RELRENT elements.
pub const DT_RELR: i64 = 36;

/// ELF RELR relocation entry.
#[repr(transparent)]
pub struct ElfRelr {
    relr: Relr,
}

impl ElfRelr {
    /// Returns the value of the relocation entry.
    #[inline]
    pub fn value(&self) -> usize {
        self.relr as usize
    }
}

/// ELF RELA relocation entry.
#[repr(transparent)]
pub struct ElfRela {
    rela: Rela,
}

impl ElfRela {
    /// Returns the relocation type.
    #[inline]
    pub fn r_type(&self) -> usize {
        self.rela.r_info as usize & REL_MASK
    }

    /// Returns the symbol index.
    #[inline]
    pub fn r_symbol(&self) -> usize {
        self.rela.r_info as usize >> REL_BIT
    }

    /// Returns the relocation offset.
    #[inline]
    pub fn r_offset(&self) -> usize {
        self.rela.r_offset as usize
    }

    /// Returns the relocation addend.
    #[inline]
    pub fn r_addend(&self, _base: usize) -> isize {
        self.rela.r_addend as isize
    }

    /// Sets the relocation offset.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rela.r_offset = offset as _;
    }
}

/// ELF REL relocation entry.
#[repr(transparent)]
pub struct ElfRel {
    rel: Rel,
}

impl ElfRel {
    /// Returns the relocation type.
    #[inline]
    pub fn r_type(&self) -> usize {
        self.rel.r_info as usize & REL_MASK
    }

    /// Returns the symbol index.
    #[inline]
    pub fn r_symbol(&self) -> usize {
        self.rel.r_info as usize >> REL_BIT
    }

    /// Returns the relocation offset.
    #[inline]
    pub fn r_offset(&self) -> usize {
        self.rel.r_offset as usize
    }

    /// Returns the relocation addend.
    ///
    /// For REL entries, the addend is stored at the relocation offset.
    ///
    /// # Arguments
    /// * `base` - The base address to add to the offset.
    #[inline]
    pub fn r_addend(&self, base: usize) -> isize {
        let ptr = (self.r_offset() + base) as *mut usize;
        unsafe { ptr.read() as isize }
    }

    /// Sets the relocation offset.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    #[cfg(feature = "object")]
    #[cfg_attr(
        all(not(target_arch = "x86"), not(target_arch = "arm")),
        allow(dead_code)
    )]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rel.r_offset = offset as _;
    }
}

#[repr(transparent)]
/// ELF symbol table entry.
///
/// This struct provides a unified interface for accessing ELF symbol information
/// regardless of whether the ELF file is 32-bit or 64-bit.
pub struct ElfSymbol {
    sym: Sym,
}

impl ElfSymbol {
    /// Returns the symbol value.
    #[inline]
    pub fn st_value(&self) -> usize {
        self.sym.st_value as usize
    }

    /// Returns the symbol binding.
    #[inline]
    pub fn st_bind(&self) -> u8 {
        self.sym.st_info >> 4
    }

    /// Returns the symbol type.
    #[inline]
    pub fn st_type(&self) -> u8 {
        self.sym.st_info & 0xf
    }

    /// Returns the section index.
    #[inline]
    pub fn st_shndx(&self) -> usize {
        self.sym.st_shndx as usize
    }

    /// Returns the symbol name index.
    #[inline]
    pub fn st_name(&self) -> usize {
        self.sym.st_name as usize
    }

    /// Returns the symbol size.
    #[inline]
    pub fn st_size(&self) -> usize {
        self.sym.st_size as usize
    }

    /// Returns the symbol visibility.
    #[inline]
    pub fn st_other(&self) -> u8 {
        self.sym.st_other
    }

    /// Returns true if the symbol is undefined (not defined in this object file).
    /// Undefined symbols typically need to be resolved from other object files or libraries.
    #[inline]
    pub fn is_undef(&self) -> bool {
        self.st_shndx() == SHN_UNDEF as usize
    }

    /// Returns true if the symbol has a valid binding type for relocation.
    /// Valid bindings include global, weak, and GNU unique symbols.
    #[inline]
    pub fn is_ok_bind(&self) -> bool {
        (1 << self.st_bind()) & OK_BINDS != 0
    }

    /// Returns true if the symbol has a valid type for relocation.
    /// Valid types include object, function, common, TLS, and GNU IFUNC symbols.
    #[inline]
    pub fn is_ok_type(&self) -> bool {
        (1 << self.st_type()) & OK_TYPES != 0
    }

    /// Returns true if the symbol has local binding.
    /// Local symbols are only visible within the object file that defines them.
    #[inline]
    pub fn is_local(&self) -> bool {
        self.st_bind() == STB_LOCAL
    }

    /// Returns true if the symbol has weak binding.
    /// Weak symbols can be overridden by global symbols with the same name.
    #[inline]
    pub fn is_weak(&self) -> bool {
        self.st_bind() == STB_WEAK
    }

    /// Sets the symbol value.
    /// This is used internally when resolving symbol addresses during loading.
    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn set_value(&mut self, value: usize) {
        self.sym.st_value = value as _;
    }
}

/// ELF program header describing segments to be loaded into memory.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfPhdr {
    phdr: Phdr,
}

/// ELF section header describing sections of the ELF file.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfShdr {
    shdr: Shdr,
}

impl ElfShdr {
    /// Creates a new ELF section header with the specified parameters.
    ///
    /// # Arguments
    /// * `sh_name` - Section name string table index
    /// * `sh_type` - Section type (e.g., PROGBITS, SYMTAB, etc.)
    /// * `sh_flags` - Section flags (e.g., WRITE, ALLOC, EXECINSTR)
    /// * `sh_addr` - Address where section should be loaded
    /// * `sh_offset` - Offset of section in file
    /// * `sh_size` - Size of section in bytes
    /// * `sh_link` - Link to another section (interpretation depends on section type)
    /// * `sh_info` - Extra information (interpretation depends on section type)
    /// * `sh_addralign` - Address alignment constraint
    /// * `sh_entsize` - Size of each entry if section contains a table
    #[cfg(feature = "object")]
    pub(crate) fn new(
        sh_name: u32,
        sh_type: u32,
        sh_flags: usize,
        sh_addr: usize,
        sh_offset: usize,
        sh_size: usize,
        sh_link: u32,
        sh_info: u32,
        sh_addralign: usize,
        sh_entsize: usize,
    ) -> Self {
        Self {
            shdr: Shdr {
                sh_name,
                sh_type,
                sh_flags: sh_flags as _,
                sh_addr: sh_addr as _,
                sh_offset: sh_offset as _,
                sh_size: sh_size as _,
                sh_link,
                sh_info,
                sh_addralign: sh_addralign as _,
                sh_entsize: sh_entsize as _,
            },
        }
    }
}

impl Deref for ElfShdr {
    type Target = Shdr;

    fn deref(&self) -> &Self::Target {
        &self.shdr
    }
}

impl DerefMut for ElfShdr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.shdr
    }
}

impl ElfShdr {
    /// Returns a reference to the section content as a slice of the specified type.
    ///
    /// This method provides safe access to section data by interpreting the section
    /// as a contiguous array of elements of type `T`. The section must contain a table
    /// of fixed-size entries for this to be meaningful.
    ///
    /// # Safety
    /// The caller must ensure that the section actually contains valid data of type `T`
    /// and that the alignment and size constraints are met.
    ///
    /// # Panics
    /// Panics in debug builds if the element size doesn't match the section's entry size,
    /// if the section size is not divisible by the entry size, or if the address is not
    /// properly aligned.
    #[cfg(feature = "object")]
    pub(crate) fn content<T>(&self) -> &'static [T] {
        self.content_mut()
    }

    /// Returns a mutable reference to the section content as a slice of the specified type.
    ///
    /// This method provides mutable access to section data. Use with caution as it allows
    /// modification of the underlying ELF data.
    ///
    /// # Safety
    /// The caller must ensure that the section actually contains valid data of type `T`
    /// and that the alignment and size constraints are met. Modifying section data may
    /// corrupt the ELF file or cause runtime errors.
    ///
    /// # Panics
    /// Panics in debug builds if the element size doesn't match the section's entry size,
    /// if the section size is not divisible by the entry size, or if the address is not
    /// properly aligned.
    #[cfg(feature = "object")]
    pub(crate) fn content_mut<T>(&self) -> &'static mut [T] {
        let start = self.sh_addr as usize;
        let len = (self.sh_size / self.sh_entsize) as usize;
        debug_assert!(core::mem::size_of::<T>() == self.sh_entsize as usize);
        debug_assert!(self.sh_size % self.sh_entsize == 0);
        debug_assert!(self.sh_addr % self.sh_addralign == 0);
        unsafe { core::slice::from_raw_parts_mut(start as *mut T, len) }
    }
}

impl Deref for ElfPhdr {
    type Target = Phdr;

    fn deref(&self) -> &Self::Target {
        &self.phdr
    }
}

impl DerefMut for ElfPhdr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.phdr
    }
}

impl Clone for ElfPhdr {
    fn clone(&self) -> Self {
        Self {
            phdr: Phdr {
                p_type: self.phdr.p_type,
                p_flags: self.phdr.p_flags,
                p_align: self.phdr.p_align,
                p_offset: self.phdr.p_offset,
                p_vaddr: self.phdr.p_vaddr,
                p_paddr: self.phdr.p_paddr,
                p_filesz: self.phdr.p_filesz,
                p_memsz: self.phdr.p_memsz,
            },
        }
    }
}

/// Architecture-specific relocation entry type.
///
/// This type alias selects the appropriate relocation entry type based on the target
/// architecture:
/// - For x86 and ARM architectures: `ElfRel` (implicit addends)
/// - For other architectures: `ElfRela` (explicit addends)
///
/// This allows code to work with relocations in a generic way without needing to
/// know the specific architecture details.
#[cfg(all(not(target_arch = "x86"), not(target_arch = "arm")))]
pub type ElfRelType = ElfRela;
#[cfg(any(target_arch = "x86", target_arch = "arm"))]
pub type ElfRelType = ElfRel;

#[cfg(all(not(target_arch = "x86"), not(target_arch = "arm")))]
#[cfg(feature = "object")]
pub(crate) const ELF_REL_SECTION_TYPE: u32 = SHT_RELA;
#[cfg(any(target_arch = "x86", target_arch = "arm"))]
#[cfg(feature = "object")]
pub(crate) const ELF_REL_SECTION_TYPE: u32 = SHT_REL;

impl ElfRelType {
    /// Return a human readable relocation type name for the current arch
    #[inline]
    pub fn r_type_str(&self) -> &'static str {
        let r_type = self.r_type();
        rel_type_to_str(r_type)
    }
}
