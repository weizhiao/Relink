//! ELF symbol table handling
//!
//! This module provides functionality for working with ELF symbol tables,
//! including symbol lookup, string table access, and symbol information management.
//! It serves as a bridge between the raw ELF data structures and the higher-level
//! symbol resolution APIs.

use super::hash::{PreCompute, sysv_hash};
use super::{
    layout::{ElfLayout, NativeElfLayout},
    raw::ElfSymRaw,
};
use crate::{elf::HashTable, memory::MappedView};
use core::{
    ffi::CStr,
    fmt::{self, Debug, Display},
};
use elf::abi::*;

/// Semantic wrapper for the ELF symbol binding field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfSymbolBind(u8);

impl ElfSymbolBind {
    /// `STB_LOCAL`: symbol is local to the object.
    pub const LOCAL: Self = Self(STB_LOCAL);
    /// `STB_GLOBAL`: symbol participates in global lookup.
    pub const GLOBAL: Self = Self(STB_GLOBAL);
    /// `STB_WEAK`: symbol has weak binding.
    pub const WEAK: Self = Self(STB_WEAK);
    /// `STB_GNU_UNIQUE`: GNU unique symbol binding.
    pub const GNU_UNIQUE: Self = Self(STB_GNU_UNIQUE);

    /// Creates a symbol binding wrapper from a raw `st_info` binding value.
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the raw binding value.
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
    /// `STT_NOTYPE`: symbol has no specified type.
    pub const NOTYPE: Self = Self(STT_NOTYPE);
    /// `STT_OBJECT`: data object symbol.
    pub const OBJECT: Self = Self(STT_OBJECT);
    /// `STT_FUNC`: function symbol.
    pub const FUNC: Self = Self(STT_FUNC);
    /// `STT_SECTION`: section symbol.
    pub const SECTION: Self = Self(STT_SECTION);
    /// `STT_FILE`: source file symbol.
    pub const FILE: Self = Self(STT_FILE);
    /// `STT_COMMON`: common block symbol.
    pub const COMMON: Self = Self(STT_COMMON);
    /// `STT_TLS`: thread-local storage symbol.
    pub const TLS: Self = Self(STT_TLS);
    /// `STT_GNU_IFUNC`: GNU indirect function symbol.
    pub const GNU_IFUNC: Self = Self(STT_GNU_IFUNC);

    /// Creates a symbol type wrapper from a raw `st_info` type value.
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the raw symbol type value.
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

/// Semantic wrapper for the visibility encoded in the ELF symbol `st_other` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfSymbolVisibility(u8);

impl ElfSymbolVisibility {
    /// `STV_DEFAULT`: symbol visibility follows its binding.
    pub const DEFAULT: Self = Self(STV_DEFAULT);
    /// `STV_INTERNAL`: symbol is hidden with processor-specific internal semantics.
    pub const INTERNAL: Self = Self(STV_INTERNAL);
    /// `STV_HIDDEN`: symbol is not visible outside its defining object.
    pub const HIDDEN: Self = Self(STV_HIDDEN);
    /// `STV_PROTECTED`: symbol is visible but cannot be preempted within its defining object.
    pub const PROTECTED: Self = Self(STV_PROTECTED);

    /// Extracts symbol visibility from a raw `st_other` value.
    #[inline]
    pub const fn new(st_other: u8) -> Self {
        Self(st_other & 0x3)
    }

    /// Returns the raw visibility value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }
}

impl From<u8> for ElfSymbolVisibility {
    #[inline]
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<ElfSymbolVisibility> for u8 {
    #[inline]
    fn from(value: ElfSymbolVisibility) -> Self {
        value.raw()
    }
}

impl Display for ElfSymbolVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            STV_DEFAULT => f.write_str("STV_DEFAULT"),
            STV_INTERNAL => f.write_str("STV_INTERNAL"),
            STV_HIDDEN => f.write_str("STV_HIDDEN"),
            STV_PROTECTED => f.write_str("STV_PROTECTED"),
            raw => write!(f, "unknown ELF symbol visibility {raw}"),
        }
    }
}

/// Semantic wrapper for the ELF symbol `st_shndx` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfSectionIndex(u16);

impl ElfSectionIndex {
    /// `SHN_UNDEF`: undefined symbol section index.
    pub const UNDEF: Self = Self(SHN_UNDEF);
    /// `SHN_ABS`: absolute symbol section index.
    pub const ABS: Self = Self(SHN_ABS);
    /// `SHN_COMMON`: common symbol section index.
    pub const COMMON: Self = Self(SHN_COMMON);
    /// `SHN_XINDEX`: extended section index marker.
    pub const XINDEX: Self = Self(SHN_XINDEX);

    /// Creates a section-index wrapper from a raw `st_shndx` value.
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the raw `st_shndx` value.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Returns the section index as `usize`.
    #[inline]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// Returns whether this is `SHN_UNDEF`.
    #[inline]
    pub const fn is_undef(self) -> bool {
        self.0 == SHN_UNDEF
    }

    /// Returns whether this is `SHN_ABS`.
    #[inline]
    pub const fn is_abs(self) -> bool {
        self.0 == SHN_ABS
    }

    /// Returns whether this is `SHN_COMMON`.
    #[inline]
    pub const fn is_common(self) -> bool {
        self.0 == SHN_COMMON
    }

    /// Returns whether this is `SHN_XINDEX`.
    #[inline]
    pub const fn is_xindex(self) -> bool {
        self.0 == SHN_XINDEX
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

const OK_BINDS: usize = 1 << STB_GLOBAL | 1 << STB_WEAK | 1 << STB_GNU_UNIQUE;

const OK_TYPES: usize = 1 << STT_NOTYPE
    | 1 << STT_OBJECT
    | 1 << STT_FUNC
    | 1 << STT_COMMON
    | 1 << STT_TLS
    | 1 << STT_GNU_IFUNC;

/// ELF symbol table entry.
///
/// This struct provides a unified interface for accessing ELF symbol information
/// regardless of whether the ELF file is 32-bit or 64-bit.
#[repr(transparent)]
pub struct ElfSymbol<L: ElfLayout = NativeElfLayout> {
    sym: L::Sym,
}

impl<L: ElfLayout> Clone for ElfSymbol<L> {
    fn clone(&self) -> Self {
        Self {
            sym: L::Sym::from_fields(
                self.st_name(),
                self.st_value(),
                self.st_size(),
                self.sym.st_info(),
                self.st_other(),
                self.st_shndx().raw(),
            ),
        }
    }
}

impl<L: ElfLayout> ElfSymbol<L> {
    pub(crate) fn synthetic(
        name: usize,
        value: usize,
        size: usize,
        bind: ElfSymbolBind,
        symbol_type: ElfSymbolType,
        other: u8,
        section_index: ElfSectionIndex,
    ) -> Self {
        let st_info = (bind.raw() << 4) | (symbol_type.raw() & 0xf);
        Self {
            sym: L::Sym::from_fields(name, value, size, st_info, other, section_index.raw()),
        }
    }

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

    /// Returns the symbol visibility encoded in `st_other`.
    #[inline]
    pub fn visibility(&self) -> ElfSymbolVisibility {
        ElfSymbolVisibility::new(self.sym.st_other())
    }

    /// Returns the raw ELF `st_other` field, including non-visibility bits.
    #[inline]
    pub fn st_other(&self) -> u8 {
        self.sym.st_other()
    }

    /// Returns true if the symbol is undefined (not defined in this object file).
    #[inline]
    pub fn is_undef(&self) -> bool {
        self.st_shndx().is_undef()
    }

    /// Returns whether this symbol can define a normal cross-module lookup.
    #[inline]
    pub fn is_exported(&self) -> bool {
        !self.is_undef()
            && (1 << self.bind().raw()) & OK_BINDS != 0
            && (1 << self.symbol_type().raw()) & OK_TYPES != 0
            && matches!(
                self.visibility(),
                ElfSymbolVisibility::DEFAULT | ElfSymbolVisibility::PROTECTED
            )
    }

    /// Returns whether references to this symbol must bind within its component.
    #[inline]
    pub fn binds_local(&self) -> bool {
        self.bind() == ElfSymbolBind::LOCAL || self.visibility() != ElfSymbolVisibility::DEFAULT
    }

    /// Returns true if the symbol has weak binding.
    #[inline]
    pub fn is_weak(&self) -> bool {
        self.bind() == ElfSymbolBind::WEAK
    }

    /// Sets the symbol value.
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
    /// Borrowed view of the raw string table bytes.
    view: MappedView<u8>,
}

impl Clone for ElfStringTable {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            view: self.view.clone(),
        }
    }
}

impl ElfStringTable {
    /// Create a new string table wrapper from a mapped byte view.
    #[inline]
    pub(crate) const fn new(view: MappedView<u8>) -> Self {
        Self { view }
    }

    #[inline]
    fn bytes_from(&self, offset: usize) -> &'static [u8] {
        let bytes = self.view.as_slice();
        assert!(
            offset <= bytes.len(),
            "ELF string table offset is out of bounds"
        );
        &bytes[offset..]
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
        let bytes = self.bytes_from(offset);
        let len =
            memchr::memchr(0, bytes).expect("ELF string table entry is missing a NUL terminator");
        // SAFETY: memchr found the first NUL inside bytes; this slice includes it.
        unsafe { CStr::from_bytes_with_nul_unchecked(&bytes[..=len]) }
    }

    /// Compare a candidate name without first finding its length.
    /// `name` must not contain NUL bytes.
    /// Missing terminators and entries shorter than the query do not match.
    #[inline]
    pub(crate) fn matches_name(&self, offset: usize, name: &[u8]) -> bool {
        let bytes = self.bytes_from(offset);
        // The terminator check bounds the comparison.
        bytes.get(name.len()) == Some(&0) && bytes[..name.len()] == *name
    }
}

/// Read-only symbol table view shared by dynamic and relocatable symbol tables.
pub struct SymbolTableView<'symtab, L: ElfLayout = NativeElfLayout> {
    pub(crate) symbols: &'symtab [ElfSymbol<L>],
    pub(crate) strtab: &'symtab ElfStringTable,
    #[cfg(feature = "version")]
    pub(crate) version: Option<&'symtab super::version::ELFVersion>,
}

impl<'symtab, L: ElfLayout> Copy for SymbolTableView<'symtab, L> {}

impl<'symtab, L: ElfLayout> Clone for SymbolTableView<'symtab, L> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

/// Read-only dynamic symbol table of an ELF file.
pub struct SymbolTable<L: ElfLayout = NativeElfLayout> {
    /// Hash table for efficient symbol lookup.
    pub(crate) hashtab: HashTable<L>,

    /// Symbol table entries.
    pub(crate) symbols: &'static [ElfSymbol<L>],

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
            .finish()
    }
}

// Safety: dynamic symbol and version tables are immutable views over retained
// module mappings. Lookups only read them while the owning module keeps the
// mapping alive.
unsafe impl<L: ElfLayout> Send for SymbolTable<L> {}

// Safety: see the Send impl above; shared access performs immutable symbol and
// version lookups only.
unsafe impl<L: ElfLayout> Sync for SymbolTable<L> {}

impl<L: ElfLayout> Clone for SymbolTable<L> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            hashtab: self.hashtab.clone(),
            symbols: self.symbols,
            strtab: self.strtab.clone(),
            #[cfg(feature = "version")]
            version: self.version.clone(),
        }
    }
}

/// Information about a specific symbol.
#[derive(Clone)]
pub(crate) struct SymbolInfo<'symtab> {
    /// The symbol name.
    name: &'symtab [u8],

    /// Optional symbol version information.
    #[cfg(feature = "version")]
    version: Option<super::version::SymbolVersion<'symtab>>,
}

impl<'symtab> Debug for SymbolInfo<'symtab> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_struct("SymbolInfo");
        debug.field("name", &self.name.escape_ascii());
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
    #[inline]
    #[allow(unused_variables)]
    pub(crate) fn from_bytes(name: &'symtab [u8], version: Option<&'symtab [u8]>) -> Self {
        SymbolInfo {
            name,
            #[cfg(feature = "version")]
            version: version.map(super::version::SymbolVersion::new),
        }
    }

    /// Returns the name of the symbol.
    #[inline]
    pub(crate) fn name(&self) -> &'symtab [u8] {
        self.name
    }

    /// Returns the symbol version information.
    #[cfg(feature = "version")]
    pub(crate) fn version(&self) -> Option<&super::version::SymbolVersion<'symtab>> {
        self.version.as_ref()
    }
}

/// Symbol lookup request plus reusable hash precomputation state.
///
/// The requested name and version remain fixed throughout a lookup. Mutable
/// access is provided for hash caching; export backends must not replace the
/// request or change its name or version.
///
/// Names and versions are matched as raw bytes without a trailing NUL.
/// UTF-8 strings and byte slices are both accepted.
/// Symbol names must not contain any NUL bytes. This is not validated;
/// names containing NUL bytes are unsupported and their lookup results are
/// unspecified.
pub struct SymbolLookup<'symbol> {
    info: SymbolInfo<'symbol>,
    precompute: PreCompute,
    // Only relocation lookups in the requesting module carry this hint.
    // Store an address for membership checks, never for dereferencing.
    symbol_hint: usize,
}

impl<'symbol> SymbolLookup<'symbol> {
    /// Creates a lookup request for an unversioned symbol name.
    ///
    /// `name` must not contain any NUL bytes. This requirement is not validated.
    #[inline]
    pub fn new(name: &'symbol (impl AsRef<[u8]> + ?Sized)) -> Self {
        Self::from_info(SymbolInfo::from_bytes(name.as_ref(), None))
    }

    #[cfg(feature = "version")]
    /// Creates a lookup request for a symbol name constrained to one version.
    ///
    /// `name` must not contain any NUL bytes. This requirement is not validated.
    #[inline]
    pub fn with_version(
        name: &'symbol (impl AsRef<[u8]> + ?Sized),
        version: &'symbol (impl AsRef<[u8]> + ?Sized),
    ) -> Self {
        Self::from_info(SymbolInfo::from_bytes(
            name.as_ref(),
            Some(version.as_ref()),
        ))
    }

    #[inline]
    pub(crate) fn from_info(info: SymbolInfo<'symbol>) -> Self {
        let precompute = PreCompute::new();
        Self {
            info,
            precompute,
            symbol_hint: 0,
        }
    }

    #[inline]
    pub(crate) fn set_symbol_hint(&mut self, address: Option<usize>) {
        self.symbol_hint = address.unwrap_or(0);
    }

    #[inline]
    pub(crate) fn symbol_hint(&self) -> Option<usize> {
        (self.symbol_hint != 0).then_some(self.symbol_hint)
    }

    /// Returns the requested symbol name as bytes without a trailing NUL.
    #[inline]
    pub fn name(&self) -> &'symbol [u8] {
        self.info.name()
    }

    /// Returns the requested GNU symbol version, when versioned lookup is
    /// enabled and the request carries one.
    #[inline]
    pub(crate) fn version_name(&self) -> Option<&[u8]> {
        #[cfg(feature = "version")]
        {
            self.info.version().map(|version| version.name())
        }
        #[cfg(not(feature = "version"))]
        {
            None
        }
    }

    #[inline]
    pub(crate) fn gnu_hash(&mut self) -> u32 {
        if let Some(hash) = self.precompute.gnuhash {
            hash
        } else {
            let hash = super::hash::gnu_hash(self.name());
            self.precompute.gnuhash = Some(hash);
            hash
        }
    }

    #[inline]
    pub(crate) fn sysv_hash(&mut self) -> u32 {
        if let Some(hash) = self.precompute.hash {
            hash
        } else {
            let hash = sysv_hash(self.name());
            self.precompute.hash = Some(hash);
            hash
        }
    }

    /// Spreads the cached GNU hash across internal table bucket and fingerprint bits.
    #[inline]
    pub(crate) fn index_hash(&mut self) -> u64 {
        u64::from(self.gnu_hash()).wrapping_mul(0x9e37_79b9_7f4a_7c15)
    }

    #[inline]
    #[cfg(feature = "version")]
    pub(crate) fn version(&self) -> Option<&super::version::SymbolVersion<'symbol>> {
        self.info.version()
    }
}

/// Symbol table entry plus its lookup metadata.
pub struct SymbolEntry<'symtab, L: ElfLayout> {
    symbol: &'symtab ElfSymbol<L>,
    info: SymbolInfo<'symtab>,
}

impl<'symtab, L: ElfLayout> SymbolEntry<'symtab, L> {
    #[inline]
    pub(crate) const fn new(symbol: &'symtab ElfSymbol<L>, info: SymbolInfo<'symtab>) -> Self {
        Self { symbol, info }
    }

    /// Returns the raw ELF symbol table entry.
    #[inline]
    pub const fn symbol(&self) -> &'symtab ElfSymbol<L> {
        self.symbol
    }

    /// Returns symbol name and version lookup metadata.
    #[inline]
    pub(crate) const fn info(&self) -> &SymbolInfo<'symtab> {
        &self.info
    }

    /// Returns the symbol name as bytes without a trailing NUL.
    #[inline]
    pub fn name(&self) -> &'symtab [u8] {
        self.info.name()
    }
}

impl<L: ElfLayout> SymbolTable<L> {
    /// Borrows the symbol entries, names, and version information.
    #[inline]
    pub fn view(&self) -> SymbolTableView<'_, L> {
        SymbolTableView {
            symbols: self.symbols,
            strtab: &self.strtab,
            #[cfg(feature = "version")]
            version: self.version.as_ref(),
        }
    }

    /// Returns a reference to the string table.
    pub(crate) fn strtab(&self) -> &ElfStringTable {
        &self.strtab
    }

    /// Looks up a symbol using the table's ELF hash index.
    #[inline]
    pub(crate) fn lookup(&self, lookup: &mut SymbolLookup<'_>) -> Option<&ElfSymbol<L>> {
        self.hashtab.lookup(self.view(), lookup)
    }

    /// Looks up a symbol by its name.
    pub fn lookup_by_name(&self, name: impl AsRef<[u8]>) -> Option<&ElfSymbol<L>> {
        let mut lookup = SymbolLookup::new(name.as_ref());
        self.lookup(&mut lookup)
    }
}

impl<'symtab, L: ElfLayout> SymbolTableView<'symtab, L> {
    /// Returns the raw symbol at `index` when it lies inside mapped memory.
    #[inline]
    pub(crate) fn get_raw(&self, index: usize) -> Option<&'symtab ElfSymbol<L>> {
        self.symbols.get(index)
    }

    /// Returns the symbol table entry for the given index.
    pub fn entry(&self, index: usize) -> SymbolEntry<'symtab, L> {
        let symbol = &self.symbols[index];
        SymbolEntry::new(
            symbol,
            SymbolInfo {
                name: self.strtab.get_cstr(symbol.st_name()).to_bytes(),
                #[cfg(feature = "version")]
                version: self.get_requirement(index),
            },
        )
    }
}
