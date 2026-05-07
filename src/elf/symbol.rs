//! ELF symbol table handling
//!
//! This module provides functionality for working with ELF symbol tables,
//! including symbol lookup, string table access, and symbol information management.
//! It serves as a bridge between the raw ELF data structures and the higher-level
//! symbol resolution APIs.

use super::defs::{ElfLayout, ElfSymRaw, NativeElfLayout};
use crate::elf::{ElfDynamic, HashTable, PreCompute};
use core::ffi::CStr;
use core::fmt::{self, Debug, Display};
use elf::abi::{
    SHN_ABS, SHN_COMMON, SHN_UNDEF, SHN_XINDEX, STB_GLOBAL, STB_GNU_UNIQUE, STB_LOCAL, STB_WEAK,
    STT_COMMON, STT_FILE, STT_FUNC, STT_GNU_IFUNC, STT_NOTYPE, STT_OBJECT, STT_SECTION, STT_TLS,
};

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

#[allow(unused)]
#[repr(C)]
/// 32-bit ELF symbol table entry.
/// This struct represents the native 32-bit symbol format used in ELF32 files.
/// For 64-bit targets, the active native symbol layout resolves to `elf::symbol::Elf64_Sym`.
pub struct Elf32Sym {
    pub st_name: u32,
    pub st_value: u32,
    pub st_size: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
}

#[repr(transparent)]
/// ELF symbol table entry.
///
/// This struct provides a unified interface for accessing ELF symbol information
/// regardless of whether the ELF file is 32-bit or 64-bit.
pub struct ElfSymbol<L: ElfLayout = NativeElfLayout> {
    sym: L::Sym,
}

impl<L: ElfLayout> ElfSymbol<L> {
    /// Returns the symbol value.
    #[inline]
    pub fn st_value(&self) -> usize {
        self.sym.st_value()
    }

    /// Returns the parsed ELF symbol binding.
    #[inline]
    pub fn bind(&self) -> ElfSymbolBind {
        ElfSymbolBind::new(self.sym.st_info() >> 4)
    }

    /// Returns the parsed ELF symbol type.
    #[inline]
    pub fn symbol_type(&self) -> ElfSymbolType {
        ElfSymbolType::new(self.sym.st_info() & 0xf)
    }

    /// Returns the section index.
    #[inline]
    pub fn st_shndx(&self) -> ElfSectionIndex {
        ElfSectionIndex::new(self.sym.st_shndx())
    }

    /// Returns the symbol name index.
    #[inline]
    pub fn st_name(&self) -> usize {
        self.sym.st_name()
    }

    /// Returns the symbol size.
    #[inline]
    pub fn st_size(&self) -> usize {
        self.sym.st_size()
    }

    /// Returns the symbol visibility.
    #[inline]
    pub fn st_other(&self) -> u8 {
        self.sym.st_other()
    }

    /// Returns true if the symbol is undefined (not defined in this object file).
    /// Undefined symbols typically need to be resolved from other object files or libraries.
    #[inline]
    pub fn is_undef(&self) -> bool {
        self.st_shndx().is_undef()
    }

    /// Returns true if the symbol has a valid binding type for relocation.
    /// Valid bindings include global, weak, and GNU unique symbols.
    #[inline]
    pub fn is_ok_bind(&self) -> bool {
        (1 << self.bind().raw()) & OK_BINDS != 0
    }

    /// Returns true if the symbol has a valid type for relocation.
    /// Valid types include object, function, common, TLS, and GNU IFUNC symbols.
    #[inline]
    pub fn is_ok_type(&self) -> bool {
        (1 << self.symbol_type().raw()) & OK_TYPES != 0
    }

    /// Returns true if the symbol has local binding.
    /// Local symbols are only visible within the object file that defines them.
    #[inline]
    pub fn is_local(&self) -> bool {
        self.bind() == ElfSymbolBind::LOCAL
    }

    /// Returns true if the symbol has weak binding.
    /// Weak symbols can be overridden by global symbols with the same name.
    #[inline]
    pub fn is_weak(&self) -> bool {
        self.bind() == ElfSymbolBind::WEAK
    }

    /// Sets the symbol value.
    /// This is used internally when resolving symbol addresses during loading.
    #[inline]
    pub(crate) fn set_value(&mut self, value: usize) {
        self.sym.set_st_value(value);
    }
}

/// ELF string table wrapper
///
/// This structure provides safe access to the ELF string table, which contains
/// null-terminated strings for symbol names and other ELF metadata.
pub(crate) struct ElfStringTable {
    /// Pointer to the raw string table data in memory
    data: *const u8,
}

impl ElfStringTable {
    /// Create a new string table wrapper from a raw pointer
    ///
    /// # Arguments
    /// * `data` - Pointer to the string table data in memory
    ///
    /// # Returns
    /// A new ElfStringTable instance
    pub(crate) const fn new(data: *const u8) -> Self {
        ElfStringTable { data }
    }

    /// Get a C-style string from the string table at the specified offset
    ///
    /// # Arguments
    /// * `offset` - Byte offset within the string table where the string starts
    ///
    /// # Returns
    /// A static reference to the C-style string at the specified offset
    #[inline]
    pub(crate) fn get_cstr(&self, offset: usize) -> &'static CStr {
        unsafe {
            let start = self.data.add(offset).cast();
            CStr::from_ptr(start)
        }
    }

    /// Convert a C-style string to a Rust string slice
    ///
    /// # Arguments
    /// * `s` - The C-style string to convert
    ///
    /// # Returns
    /// A string slice containing the same data as the C-style string
    #[inline]
    fn convert_cstr(s: &CStr) -> &str {
        unsafe { core::str::from_utf8_unchecked(s.to_bytes()) }
    }

    /// Get a Rust string slice from the string table at the specified offset
    ///
    /// This method combines [get_cstr] and [convert_cstr] to directly return
    /// a Rust string slice for the string at the specified offset.
    ///
    /// # Arguments
    /// * `offset` - Byte offset within the string table where the string starts
    ///
    /// # Returns
    /// A static reference to the Rust string at the specified offset
    #[inline]
    pub(crate) fn get_str(&self, offset: usize) -> &'static str {
        Self::convert_cstr(self.get_cstr(offset))
    }
}

/// Symbol table of an ELF file.
pub struct SymbolTable<L: ElfLayout = NativeElfLayout> {
    /// Hash table for efficient symbol lookup.
    pub(crate) hashtab: HashTable,

    /// Pointer to the symbol table.
    pub(crate) symtab: *const ElfSymbol<L>,

    /// String table for symbol names.
    pub(crate) strtab: ElfStringTable,

    /// Optional symbol version information.
    #[cfg(feature = "version")]
    pub(crate) version: Option<super::version::ELFVersion>,
}

impl<L: ElfLayout> Debug for SymbolTable<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SymbolTable")
            .field("hashtab", &self.hashtab)
            .field("symtab_ptr", &self.symtab)
            .finish()
    }
}

/// Information about a specific symbol.
pub struct SymbolInfo<'symtab> {
    /// The symbol name.
    name: &'symtab str,

    /// The symbol name as a C-style string.
    cname: Option<&'symtab CStr>,

    /// Optional symbol version information.
    #[cfg(feature = "version")]
    version: Option<super::version::SymbolVersion<'symtab>>,
}

impl<'symtab> Debug for SymbolInfo<'symtab> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_struct("SymbolInfo");
        debug.field("name", &self.name);
        #[cfg(feature = "version")]
        {
            if let Some(v) = &self.version {
                debug.field("version", v);
            }
        }
        debug.finish()
    }
}

impl<'symtab> SymbolInfo<'symtab> {
    /// Creates a new `SymbolInfo` from a name and optional version.
    #[allow(unused_variables)]
    pub fn from_str(name: &'symtab str, version: Option<&'symtab str>) -> Self {
        SymbolInfo {
            name,
            cname: None,
            #[cfg(feature = "version")]
            version: version.map(super::version::SymbolVersion::new),
        }
    }

    /// Returns the name of the symbol.
    #[inline]
    pub fn name(&self) -> &'symtab str {
        self.name
    }

    /// Returns the C-style name of the symbol, if available.
    #[inline]
    pub fn cname(&self) -> Option<&'symtab CStr> {
        self.cname
    }

    /// Returns the symbol version information.
    #[cfg(feature = "version")]
    pub(crate) fn version(&self) -> Option<&super::version::SymbolVersion<'symtab>> {
        self.version.as_ref()
    }
}

impl<L: ElfLayout> SymbolTable<L> {
    /// Creates a symbol table from ELF dynamic section information.
    pub(crate) fn from_dynamic<Arch>(dynamic: &ElfDynamic<Arch>) -> Self
    where
        Arch: crate::relocation::RelocationArch<Layout = L>,
    {
        // Create hash table from dynamic section information
        let hashtab = HashTable::from_dynamic(dynamic);

        // Get symbol table pointer
        let symtab = dynamic.symtab as *const ElfSymbol<L>;

        // Create string table wrapper
        let strtab = ElfStringTable::new(dynamic.strtab as *const u8);

        // Create version information (when version feature is enabled)
        #[cfg(feature = "version")]
        let version = super::version::ELFVersion::new(
            dynamic.version_idx,
            dynamic.verneed,
            dynamic.verdef,
            &strtab,
        );

        SymbolTable {
            hashtab,
            symtab,
            strtab,
            #[cfg(feature = "version")]
            version,
        }
    }
    /// Returns a reference to the string table.
    pub(crate) fn strtab(&self) -> &ElfStringTable {
        &self.strtab
    }

    /// Looks up a symbol by its name.
    pub fn lookup_by_name(&self, name: impl AsRef<str>) -> Option<&ElfSymbol<L>> {
        let info = SymbolInfo::from_str(name.as_ref(), None);
        let mut precompute = info.precompute();
        self.lookup(&info, &mut precompute)
    }

    /// Looks up a symbol in the symbol table using the hash table for efficiency.
    fn lookup(&self, symbol: &SymbolInfo, precompute: &mut PreCompute) -> Option<&ElfSymbol<L>> {
        self.hashtab.lookup(self, symbol, precompute)
    }

    /// Looks up a symbol and filters based on relocation requirements.
    #[inline]
    pub(crate) fn lookup_filter(
        &self,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&ElfSymbol<L>> {
        // Look up the symbol
        if let Some(sym) = self.lookup(symbol, precompute) {
            // Filter based on relocation requirements:
            // 1. Symbol must be defined (not undefined)
            // 2. Symbol must have acceptable binding
            // 3. Symbol must have acceptable type
            if !sym.is_undef() && sym.is_ok_bind() && sym.is_ok_type() {
                return Some(sym);
            }
        }
        None
    }

    /// Returns the symbol and its information for the given index.
    pub fn symbol_idx<'symtab>(
        &'symtab self,
        idx: usize,
    ) -> (&'symtab ElfSymbol<L>, SymbolInfo<'symtab>) {
        // Get the symbol at the specified index
        let symbol = unsafe { &*self.symtab.add(idx) };

        // Get the symbol name as a C-style string
        let cname = self.strtab.get_cstr(symbol.st_name());

        // Convert to a Rust string slice
        let name = ElfStringTable::convert_cstr(cname);

        // Create and return the symbol and its information
        (
            symbol,
            SymbolInfo {
                name,
                cname: Some(cname),
                #[cfg(feature = "version")]
                version: self.get_requirement(idx),
            },
        )
    }

    /// Returns the number of symbols in the symbol table.
    #[inline]
    pub fn count_syms(&self) -> usize {
        self.hashtab.count_syms()
    }
}
