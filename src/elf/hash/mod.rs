//! ELF symbol hash table implementations
//!
//! This module provides implementations for different ELF symbol hash table formats,
//! including the traditional SYSV hash table, the GNU hash table, and a custom hash
//! implementation. These hash tables are used to efficiently locate symbols during
//! the dynamic linking process.
//!
//! The GNU hash table (.gnu.hash) is generally preferred over the traditional
//! SYSV hash table (.hash) as it provides better performance and memory usage.

use crate::elf::{
    ElfDynamic, ElfDynamicHashTab, ElfShdr, ElfStringTable, ElfSymbol, SymbolTable,
    symbol::SymbolInfo,
};
use core::fmt::Debug;
use custom::CustomHash;
use gnu::ElfGnuHash;
use sysv::ElfHash;
use traits::ElfHashTable;

mod custom;
mod gnu;
mod sysv;
mod traits;

/// An enumeration of supported ELF hash table types.
///
/// This enum represents the different hash table formats that can be used
/// for symbol lookup in ELF files. The variant used depends on what hash
/// sections are present in the ELF file.
pub(crate) enum HashTable {
    /// GNU hash table (.gnu.hash section)
    ///
    /// This is the preferred hash table format in modern ELF implementations
    /// as it provides better performance and memory efficiency compared to
    /// the traditional SYSV hash table.
    Gnu(ElfGnuHash),

    /// Traditional SYSV hash table (.hash section)
    ///
    /// This is the original ELF hash table format. While still widely supported,
    /// it is generally less efficient than the GNU hash table.
    Elf(ElfHash),

    /// Custom hash table implementation
    ///
    /// This is a fallback implementation that can be used when no standard
    /// hash sections are available.
    Custom(CustomHash),
}

impl Debug for HashTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HashTable::Gnu(_) => write!(f, "GnuHash"),
            HashTable::Elf(_) => write!(f, "ElfHash"),
            HashTable::Custom(_) => write!(f, "CustomHash"),
        }
    }
}

/// Precomputed hash values for symbol lookup optimization.
///
/// This structure holds precomputed hash values and related data that can
/// be used to speed up symbol lookups in hash tables. Precomputing these
/// values avoids repeated calculations during the lookup process.
pub struct PreCompute {
    /// GNU hash value for the symbol name
    gnuhash: u32,

    /// Filter offset for GNU hash table lookups
    fofs: usize,

    /// Filter mask for GNU hash table lookups
    fmask: usize,

    /// Traditional hash value (used for SYSV hash tables)
    hash: Option<u32>,

    /// Custom hash value (reserved for future use)
    custom: Option<u64>,
}

impl HashTable {
    /// Get the number of symbols in the hash table.
    ///
    /// # Returns
    /// The number of symbols that can be looked up in this hash table.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn count_syms(&self) -> usize {
        match &self {
            HashTable::Gnu(hashtab) => hashtab.count_syms(),
            HashTable::Elf(hashtab) => hashtab.count_syms(),
            HashTable::Custom(hashtab) => hashtab.count_syms(),
        }
    }

    /// Look up a symbol in the hash table.
    ///
    /// This method searches for a symbol in the hash table using the provided
    /// symbol information and precomputed hash values. The actual lookup
    /// implementation depends on the hash table type.
    ///
    /// # Arguments
    /// * `table` - The symbol table to search in.
    /// * `symbol` - Information about the symbol to look up.
    /// * `precompute` - Precomputed hash values to speed up the lookup.
    ///
    /// # Returns
    /// * `Some(symbol)` - A reference to the found symbol.
    /// * `None` - If the symbol was not found.
    pub(crate) fn lookup<'sym>(
        &self,
        table: &'sym SymbolTable,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&'sym ElfSymbol> {
        match self {
            HashTable::Gnu(_) => ElfGnuHash::lookup(table, symbol, precompute),
            HashTable::Elf(_) => ElfHash::lookup(table, symbol, precompute),
            HashTable::Custom(_) => CustomHash::lookup(table, symbol, precompute),
        }
    }

    /// Create a hash table from section header information.
    ///
    /// This method creates a custom hash table based on the symbol table
    /// and string table section headers. This is typically used when no
    /// standard hash sections are present in the ELF file.
    ///
    /// # Arguments
    /// * `symtab` - The symbol table section header.
    /// * `strtab` - The string table.
    ///
    /// # Returns
    /// A HashTable instance containing a custom hash implementation.
    pub(crate) fn from_shdr(symtab: &ElfShdr, strtab: &ElfStringTable) -> Self {
        HashTable::Custom(CustomHash::from_shdr(symtab, strtab))
    }

    /// Create a hash table from dynamic section information.
    ///
    /// This method creates a hash table based on the information in the
    /// ELF dynamic section. The type of hash table created depends on
    /// what hash sections are referenced in the dynamic section.
    ///
    /// # Arguments
    /// * `dynamic` - The ELF dynamic section information.
    ///
    /// # Returns
    /// A HashTable instance containing either a GNU or SYSV hash implementation.
    pub(crate) fn from_dynamic(dynamic: &ElfDynamic) -> Self {
        match dynamic.hashtab {
            ElfDynamicHashTab::Gnu(off) => HashTable::Gnu(ElfGnuHash::parse(off as *const u8)),
            ElfDynamicHashTab::Elf(off) => HashTable::Elf(ElfHash::parse(off as *const u8)),
        }
    }

    /// Get a reference to the GNU hash table, if this is one.
    ///
    /// # Returns
    /// * `Some(gnu_hash)` - A reference to the GNU hash table.
    /// * `None` - If this is not a GNU hash table.
    fn into_gnuhash(&self) -> Option<&ElfGnuHash> {
        match self {
            HashTable::Gnu(hashtab) => Some(hashtab),
            _ => None,
        }
    }

    /// Get a reference to the SYSV hash table, if this is one.
    ///
    /// # Returns
    /// * `Some(elf_hash)` - A reference to the SYSV hash table.
    /// * `None` - If this is not a SYSV hash table.
    fn into_elfhash(&self) -> Option<&ElfHash> {
        match self {
            HashTable::Elf(hashtab) => Some(hashtab),
            _ => None,
        }
    }

    /// Get a reference to the custom hash table, if this is one.
    ///
    /// # Returns
    /// * `Some(custom_hash)` - A reference to the custom hash table.
    /// * `None` - If this is not a custom hash table.
    fn into_customhash(&self) -> Option<&CustomHash> {
        match self {
            HashTable::Custom(hashtab) => Some(hashtab),
            _ => None,
        }
    }
}

impl SymbolInfo<'_> {
    /// Precompute hash values for efficient symbol lookup.
    ///
    /// This method computes and stores various hash values and related data
    /// that can be used to speed up symbol lookups in hash tables. These
    /// precomputed values help avoid repeated calculations during the
    /// lookup process.
    ///
    /// # Returns
    /// A PreCompute structure containing the precomputed hash values.
    #[inline]
    pub fn precompute(&self) -> PreCompute {
        let gnuhash = ElfGnuHash::hash(self.name().as_bytes()) as u32;
        PreCompute {
            gnuhash,
            fofs: gnuhash as usize / usize::BITS as usize,
            fmask: 1 << (gnuhash % (8 * size_of::<usize>() as u32)),
            hash: None,
            custom: None,
        }
    }
}
