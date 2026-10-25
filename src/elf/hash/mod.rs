//! ELF symbol hash table implementations
//!
//! This module provides implementations for different ELF symbol hash table formats,
//! including the traditional SYSV hash table and the GNU hash table.
//! These hash tables are used to efficiently locate symbols during
//! the dynamic linking process.
//!
//! The GNU hash table (.gnu.hash) is generally preferred over the traditional
//! SYSV hash table (.hash) as it provides better performance and memory usage.

use crate::elf::{
    ElfDynamic, ElfDynamicHashTab, ElfLayout, ElfSymbol, NativeElfLayout, SymbolLookup,
    SymbolTableView,
};
use crate::{Result, memory::RegionAccess, relocation::RelocationArch, segment::ElfSegments};
use core::fmt::Debug;
use gnu::ElfGnuHash;
use sysv::ElfHash;

/// Compute the layout-independent GNU hash of a symbol name.
#[inline]
pub(crate) fn gnu_hash(name: &[u8]) -> u32 {
    let mut hash = 5381u32;
    let mut chunks = name.chunks_exact(4);
    for chunk in &mut chunks {
        // Combine four rounds to shorten the hash dependency chain.
        hash = hash.wrapping_mul(33 * 33 * 33 * 33).wrapping_add(
            u32::from(chunk[0]) * 33 * 33 * 33
                + u32::from(chunk[1]) * 33 * 33
                + u32::from(chunk[2]) * 33
                + u32::from(chunk[3]),
        );
    }
    for byte in chunks.remainder() {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(*byte));
    }
    hash
}

#[cfg(all(feature = "libc", target_os = "linux", target_env = "gnu"))]
pub(crate) use gnu::ElfGnuHeader;
mod gnu;
mod sysv;

/// Computes the standard SYSV ELF hash used by symbol and version tables.
#[inline]
pub fn sysv_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for &byte in name {
        hash = (hash << 4) + u32::from(byte);
        let high = hash & 0xf0000000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

/// Standard dynamic ELF symbol hash table.
///
/// Dynamic ELF files may carry either a GNU hash table or the traditional SYSV
/// hash table. Both represent the same role in this loader, so the distinction
/// is kept inside this implementation detail.
pub struct HashTable<L: ElfLayout = NativeElfLayout>(HashTableKind<L>);

enum HashTableKind<L: ElfLayout = NativeElfLayout> {
    /// GNU hash table (.gnu.hash section).
    Gnu(ElfGnuHash<L>),

    /// Traditional SYSV hash table (.hash section).
    Sysv(ElfHash),
}

impl<L: ElfLayout> Clone for HashTable<L> {
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<L: ElfLayout> Clone for HashTableKind<L> {
    #[inline]
    fn clone(&self) -> Self {
        match self {
            Self::Gnu(hashtab) => Self::Gnu(hashtab.clone()),
            Self::Sysv(hashtab) => Self::Sysv(hashtab.clone()),
        }
    }
}

impl<L: ElfLayout> Debug for HashTable<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            HashTableKind::Gnu(_) => write!(f, "GnuHash"),
            HashTableKind::Sysv(_) => write!(f, "ElfHash"),
        }
    }
}

/// Hash values computed on demand and reused across a symbol lookup scope.
/// Unused table formats do not incur hashing work.
pub(in crate::elf) struct PreCompute {
    /// GNU hash value for the symbol name
    pub(in crate::elf) gnuhash: Option<u32>,

    /// Traditional hash value (used for SYSV hash tables)
    pub(in crate::elf) hash: Option<u32>,
}

impl PreCompute {
    #[inline]
    pub(in crate::elf) fn new() -> Self {
        Self {
            gnuhash: None,
            hash: None,
        }
    }
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
        Arch: RelocationArch<Layout = L>,
        R: RegionAccess,
    {
        Ok(Self(match dynamic.hashtab {
            ElfDynamicHashTab::Gnu(addr) => HashTableKind::Gnu(ElfGnuHash::parse(segments, addr)?),
            ElfDynamicHashTab::Elf(addr) => HashTableKind::Sysv(ElfHash::parse(segments, addr)?),
        }))
    }

    pub(crate) fn for_each(
        &self,
        table: SymbolTableView<'_, L>,
        visitor: &mut dyn FnMut(&ElfSymbol<L>),
    ) {
        match &self.0 {
            HashTableKind::Gnu(hashtab) => hashtab.for_each(table, visitor),
            HashTableKind::Sysv(hashtab) => hashtab.for_each(table, visitor),
        }
    }

    pub(crate) fn lookup<'sym>(
        &self,
        table: SymbolTableView<'sym, L>,
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'sym ElfSymbol<L>> {
        match &self.0 {
            HashTableKind::Gnu(hashtab) => hashtab.lookup(table, lookup),
            HashTableKind::Sysv(hashtab) => hashtab.lookup(table, lookup),
        }
    }
}
