//! ELF symbol table handling
//!
//! This module provides functionality for working with ELF symbol tables,
//! including symbol lookup, string table access, and symbol information management.
//! It serves as a bridge between the raw ELF data structures and the higher-level
//! symbol resolution APIs.

use crate::{
    elf::{ElfDynamic, HashTable, PreCompute},
    elf::{ElfShdr, ElfSymbol},
};
use core::ffi::CStr;
use core::fmt::Debug;

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
    const fn new(data: *const u8) -> Self {
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
pub struct SymbolTable {
    /// Hash table for efficient symbol lookup.
    pub(crate) hashtab: HashTable,

    /// Pointer to the symbol table.
    pub(crate) symtab: *const ElfSymbol,

    /// String table for symbol names.
    pub(crate) strtab: ElfStringTable,

    /// Optional symbol version information.
    #[cfg(feature = "version")]
    pub(crate) version: Option<super::version::ELFVersion>,
}

impl Debug for SymbolTable {
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

    /// Returns the C-style name of the symbol.
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

impl SymbolTable {
    /// Create a symbol table from ELF dynamic section information
    ///
    /// This method constructs a SymbolTable from the information provided
    /// in the ELF dynamic section, including hash tables, symbol tables,
    /// and string tables.
    ///
    /// # Arguments
    /// * `dynamic` - Reference to the ELF dynamic section information
    ///
    /// # Returns
    /// A new SymbolTable instance
    pub(crate) fn from_dynamic(dynamic: &ElfDynamic) -> Self {
        // Create hash table from dynamic section information
        let hashtab = HashTable::from_dynamic(dynamic);

        // Get symbol table pointer
        let symtab = dynamic.symtab as *const ElfSymbol;

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

    /// Create a symbol table from section headers
    ///
    /// This method constructs a SymbolTable from ELF section headers,
    /// typically used for relocatable objects that don't have dynamic sections.
    ///
    /// # Arguments
    /// * `symtab` - Reference to the symbol table section header
    /// * `shdrs` - Slice of all section headers in the ELF file
    ///
    /// # Returns
    /// A new SymbolTable instance
    pub(crate) fn from_shdrs(symtab: &ElfShdr, shdrs: &[ElfShdr]) -> Self {
        // Get the string table section header (linked via sh_link)
        let strtab_shdr = &shdrs[symtab.sh_link as usize];

        // Create string table wrapper
        let strtab = ElfStringTable::new(strtab_shdr.sh_addr as *const u8);

        // Create hash table from section headers
        let hashtab = HashTable::from_shdr(symtab, &strtab);

        Self {
            hashtab,
            symtab: symtab.sh_addr as *const ElfSymbol,
            strtab,
            #[cfg(feature = "version")]
            version: None,
        }
    }

    /// Get a reference to the string table
    ///
    /// # Returns
    /// A reference to the string table
    pub(crate) fn strtab(&self) -> &ElfStringTable {
        &self.strtab
    }

    pub fn lookup_by_name(&self, name: impl AsRef<str>) -> Option<&ElfSymbol> {
        let info = SymbolInfo::from_str(name.as_ref(), None);
        let mut precompute = info.precompute();
        self.lookup(&info, &mut precompute)
    }

    /// Look up a symbol in the symbol table
    ///
    /// This method performs a symbol lookup using the hash table for efficiency.
    ///
    /// # Arguments
    /// * `symbol` - Information about the symbol to look up
    /// * `precompute` - Precomputed hash values to speed up the lookup
    ///
    /// # Returns
    /// * `Some(symbol)` - A reference to the found symbol
    /// * `None` - If the symbol was not found
    fn lookup(&self, symbol: &SymbolInfo, precompute: &mut PreCompute) -> Option<&ElfSymbol> {
        self.hashtab.lookup(self, symbol, precompute)
    }

    /// Look up a symbol and filter based on relocation requirements
    ///
    /// This method performs a symbol lookup and additionally filters the results
    /// to only return symbols that are suitable for relocation. This includes
    /// checking that the symbol is defined, has the correct binding, and is
    /// of the correct type.
    ///
    /// # Arguments
    /// * `symbol` - Information about the symbol to look up
    /// * `precompute` - Precomputed hash values to speed up the lookup
    ///
    /// # Returns
    /// * `Some(symbol)` - A reference to the found symbol that meets relocation requirements
    /// * `None` - If no suitable symbol was found
    #[inline]
    pub(crate) fn lookup_filter(
        &self,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&ElfSymbol> {
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

    /// Get a symbol and its information by index
    ///
    /// This method retrieves a symbol and its associated information by index
    /// directly from the symbol table, bypassing the hash table lookup.
    ///
    /// # Arguments
    /// * `idx` - The index of the symbol to retrieve
    ///
    /// # Returns
    /// A tuple containing:
    /// 1. A reference to the symbol
    /// 2. SymbolInfo containing the symbol's name and other information
    pub fn symbol_idx<'symtab>(
        &'symtab self,
        idx: usize,
    ) -> (&'symtab ElfSymbol, SymbolInfo<'symtab>) {
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

    /// Get the number of symbols in the symbol table
    ///
    /// # Returns
    /// The number of symbols in the symbol table
    #[inline]
    pub fn count_syms(&self) -> usize {
        self.hashtab.count_syms()
    }
}
