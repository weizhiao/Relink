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
    ElfDynamic, ElfDynamicHashTab, ElfLayout, ElfSymbol, SymbolTable, symbol::SymbolInfo,
};
use crate::{Result, os::RegionAccess, segment::ElfSegments};
use core::fmt::Debug;
use gnu::ElfGnuHash;
use sysv::ElfHash;

mod gnu;
mod sysv;
mod traits;
pub use traits::ElfHashTable;

/// Standard dynamic ELF symbol hash table.
///
/// Dynamic ELF files may carry either a GNU hash table or the traditional SYSV
/// hash table. Both represent the same role in this loader, so the distinction
/// is kept inside this implementation detail.
pub struct HashTable<L: ElfLayout = crate::elf::NativeElfLayout>(HashTableKind<L>);

enum HashTableKind<L: ElfLayout = crate::elf::NativeElfLayout> {
    /// GNU hash table (.gnu.hash section).
    Gnu(ElfGnuHash<L>),

    /// Traditional SYSV hash table (.hash section).
    Sysv(ElfHash),
}

impl<L: ElfLayout> Debug for HashTable<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            HashTableKind::Gnu(_) => write!(f, "GnuHash"),
            HashTableKind::Sysv(_) => write!(f, "ElfHash"),
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

    /// Traditional hash value (used for SYSV hash tables)
    hash: Option<u32>,

    /// Custom hash value (reserved for future use)
    #[cfg(feature = "object")]
    pub(crate) custom: Option<u64>,
}

impl<L: ElfLayout> HashTable<L> {
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
    pub(crate) fn from_dynamic<Arch, R>(
        dynamic: &ElfDynamic<Arch>,
        segments: &ElfSegments<R>,
    ) -> Result<Self>
    where
        Arch: crate::relocation::RelocationArch<Layout = L>,
        R: RegionAccess,
    {
        Ok(Self(match dynamic.hashtab {
            ElfDynamicHashTab::Gnu(addr) => HashTableKind::Gnu(ElfGnuHash::parse(segments, addr)?),
            ElfDynamicHashTab::Elf(addr) => HashTableKind::Sysv(ElfHash::parse(segments, addr)?),
        }))
    }
}

impl<L: ElfLayout> ElfHashTable<L> for HashTable<L> {
    #[inline]
    fn count_syms(&self) -> usize {
        match &self.0 {
            HashTableKind::Gnu(hashtab) => hashtab.count_syms(),
            HashTableKind::Sysv(hashtab) => <ElfHash as ElfHashTable<L>>::count_syms(hashtab),
        }
    }

    fn lookup<'sym, H>(
        &self,
        table: &'sym SymbolTable<L, H>,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&'sym ElfSymbol<L>> {
        match &self.0 {
            HashTableKind::Gnu(hashtab) => hashtab.lookup(table, symbol, precompute),
            HashTableKind::Sysv(hashtab) => hashtab.lookup(table, symbol, precompute),
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
        let gnuhash =
            ElfGnuHash::<crate::elf::NativeElfLayout>::hash(self.name().as_bytes()) as u32;
        PreCompute {
            gnuhash,
            hash: None,
            #[cfg(feature = "object")]
            custom: None,
        }
    }
}
