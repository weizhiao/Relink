//! ELF symbol table handling
//!
//! This module provides functionality for working with ELF symbol tables,
//! including symbol lookup, string table access, and symbol information management.
//! It serves as a bridge between the raw ELF data structures and the higher-level
//! symbol resolution APIs.

use super::defs::{ElfLayout, ElfSymbol, NativeElfLayout};
use super::hash::{PreCompute, SymbolHash};
use crate::{elf::HashTable, memory::MappedView};
use core::{ffi::CStr, fmt::Debug};
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
        CStr::from_bytes_until_nul(bytes)
            .expect("ELF string table entry is missing a NUL terminator")
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
        core::str::from_utf8(s.to_bytes()).expect("ELF string table entry is not valid UTF-8")
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

/// Read-only symbol table view shared by dynamic and relocatable symbol tables.
pub struct SymbolTableView<'symtab, L: ElfLayout = NativeElfLayout, H = HashTable<L>> {
    pub(crate) hashtab: &'symtab H,
    pub(crate) symbols: &'symtab [ElfSymbol<L>],
    pub(crate) strtab: &'symtab ElfStringTable,
    #[cfg(feature = "version")]
    pub(crate) version: Option<&'symtab super::version::ELFVersion>,
}

impl<'symtab, L: ElfLayout, H> Copy for SymbolTableView<'symtab, L, H> {}

impl<'symtab, L: ElfLayout, H> Clone for SymbolTableView<'symtab, L, H> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

/// Read-only dynamic symbol table of an ELF file.
pub struct SymbolTable<L: ElfLayout = NativeElfLayout, H = HashTable<L>> {
    /// Hash table for efficient symbol lookup.
    pub(crate) hashtab: H,

    /// Symbol table entries.
    pub(crate) symbols: &'static [ElfSymbol<L>],

    /// String table for symbol names.
    pub(crate) strtab: ElfStringTable,

    /// Optional symbol version information.
    #[cfg(feature = "version")]
    pub(crate) version: Option<super::version::ELFVersion>,
}

impl<L: ElfLayout, H: Debug> Debug for SymbolTable<L, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SymbolTable")
            .field("hashtab", &self.hashtab)
            .field("symbol_count", &self.symbols.len())
            .finish()
    }
}

// Safety: dynamic symbol tables are immutable views over retained module mappings.
// Version metadata may carry raw pointers into those mappings, but lookups only
// read from them while the owning module keeps the mapping alive.
unsafe impl<L: ElfLayout> Send for SymbolTable<L, HashTable<L>> {}

// Safety: see the Send impl above; shared access performs immutable symbol and
// version lookups only.
unsafe impl<L: ElfLayout> Sync for SymbolTable<L, HashTable<L>> {}

impl<L: ElfLayout, H: Clone> Clone for SymbolTable<L, H> {
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
    name: &'symtab str,

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
    pub(crate) fn from_str(name: &'symtab str, version: Option<&'symtab str>) -> Self {
        SymbolInfo {
            name,
            #[cfg(feature = "version")]
            version: version.map(super::version::SymbolVersion::new),
        }
    }

    /// Returns the name of the symbol.
    #[inline]
    pub(crate) fn name(&self) -> &'symtab str {
        self.name
    }

    /// Returns the symbol version information.
    #[cfg(feature = "version")]
    pub(crate) fn version(&self) -> Option<&super::version::SymbolVersion<'symtab>> {
        self.version.as_ref()
    }
}

/// Symbol lookup request plus reusable hash precomputation state.
pub struct SymbolLookup<'symbol> {
    info: SymbolInfo<'symbol>,
    precompute: PreCompute,
}

impl<'symbol> SymbolLookup<'symbol> {
    #[inline]
    pub fn new(name: &'symbol str) -> Self {
        Self::from_info(SymbolInfo::from_str(name, None))
    }

    #[cfg(feature = "version")]
    #[inline]
    pub fn with_version(name: &'symbol str, version: &'symbol str) -> Self {
        Self::from_info(SymbolInfo::from_str(name, Some(version)))
    }

    #[inline]
    pub(crate) fn from_info(info: SymbolInfo<'symbol>) -> Self {
        let precompute = PreCompute::new(info.name());
        Self { info, precompute }
    }

    #[inline]
    pub fn name(&self) -> &'symbol str {
        self.info.name()
    }

    #[inline]
    pub(crate) fn gnu_hash(&self) -> u32 {
        self.precompute.gnuhash
    }

    #[inline]
    pub(crate) fn sysv_hash(&mut self, hash: impl FnOnce(&str) -> u32) -> u32 {
        if let Some(hash) = self.precompute.hash {
            hash
        } else {
            let hash = hash(self.name());
            self.precompute.hash = Some(hash);
            hash
        }
    }

    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn custom_hash(&mut self, hash: impl FnOnce(&str) -> u64) -> u64 {
        if let Some(hash) = self.precompute.custom {
            hash
        } else {
            let hash = hash(self.name());
            self.precompute.custom = Some(hash);
            hash
        }
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

    /// Returns the symbol name.
    #[inline]
    pub fn name(&self) -> &'symtab str {
        self.info.name()
    }
}

impl<L: ElfLayout, H> SymbolTable<L, H> {
    #[inline]
    pub fn view(&self) -> SymbolTableView<'_, L, H> {
        SymbolTableView {
            hashtab: &self.hashtab,
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
}

impl<'symtab, L: ElfLayout, H> SymbolTableView<'symtab, L, H> {
    /// Returns all symbol table entries.
    #[inline]
    pub fn symbols(&self) -> &'symtab [ElfSymbol<L>] {
        self.symbols
    }

    /// Returns the symbol table entry for the given index.
    pub fn symbol_idx(&self, idx: usize) -> SymbolEntry<'symtab, L> {
        // Get the symbol at the specified index
        let symbol = self
            .symbols
            .get(idx)
            .expect("ELF symbol index is out of bounds");

        // Get the symbol name as a C-style string
        let cname = self.strtab.get_cstr(symbol.st_name());

        // Convert to a Rust string slice
        let name = ElfStringTable::convert_cstr(cname);

        // Create and return the symbol and its information
        SymbolEntry::new(
            symbol,
            SymbolInfo {
                name,
                #[cfg(feature = "version")]
                version: self.get_requirement(idx),
            },
        )
    }
}

impl<'symtab, L: ElfLayout, H: SymbolHash<L>> SymbolTableView<'symtab, L, H> {
    /// Looks up a symbol in the symbol table using the hash table for efficiency.
    fn lookup(&self, lookup: &mut SymbolLookup<'_>) -> Option<&'symtab ElfSymbol<L>> {
        self.hashtab.lookup(*self, lookup)
    }

    /// Looks up a symbol and filters based on relocation requirements.
    #[inline]
    pub(crate) fn lookup_filter(
        &self,
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'symtab ElfSymbol<L>> {
        // Look up the symbol
        if let Some(sym) = self.lookup(lookup) {
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
}

impl<'symtab, L: ElfLayout> SymbolTableView<'symtab, L> {
    /// Looks up a symbol by its name.
    pub fn lookup_by_name(&self, name: impl AsRef<str>) -> Option<&'symtab ElfSymbol<L>> {
        let name = name.as_ref();
        let mut lookup = SymbolLookup::new(name);
        self.lookup(&mut lookup)
    }

    /// Returns the number of symbols in the symbol table.
    #[inline]
    pub fn count_syms(&self) -> usize {
        self.hashtab.count_syms()
    }
}
