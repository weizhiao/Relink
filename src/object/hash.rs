//! Custom ELF hash table implementation for relocatable objects.

use crate::elf::{
    ElfLayout, ElfStringTable, ElfSymbol, ElfSymbolType, PreCompute, SymbolHash, SymbolInfo,
    SymbolTableView,
};
use core::hash::{Hash, Hasher};
use foldhash::{SharedSeed, fast::FoldHasher};
use hashbrown::HashTable as RawHashTable;

#[derive(Clone)]
struct TableEntry<N> {
    name: N,
    idx: usize,
}

const HASHER: FoldHasher<'static> = FoldHasher::with_seed(0, SharedSeed::global_fixed());

#[derive(Clone)]
pub struct CustomHash<N = &'static str> {
    map: RawHashTable<TableEntry<N>>,
}

impl<N> CustomHash<N> {
    #[inline]
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            map: RawHashTable::with_capacity(capacity),
        }
    }

    pub(crate) fn hash(name: &[u8]) -> u64 {
        let mut hasher = HASHER.clone();
        name.hash(&mut hasher);
        hasher.finish()
    }

    #[inline]
    pub(crate) fn count_syms(&self) -> usize {
        self.map.len()
    }
}

impl<N: AsRef<str>> CustomHash<N> {
    #[inline]
    pub(crate) fn find_idx(&self, name: &str) -> Option<usize> {
        let hash = Self::hash(name.as_bytes());
        self.find_idx_with_hash(name, hash)
    }

    #[inline]
    pub(crate) fn lookup_idx(
        &self,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<usize> {
        let name = symbol.name();
        let hash = if let Some(hash) = precompute.custom {
            hash
        } else {
            let hash = Self::hash(name.as_bytes());
            precompute.custom = Some(hash);
            hash
        };

        self.find_idx_with_hash(name, hash)
    }

    #[inline]
    pub(crate) fn insert_unique(&mut self, name: N, idx: usize) {
        let hash = Self::hash(name.as_ref().as_bytes());
        self.map
            .insert_unique(hash, TableEntry { name, idx }, |val| {
                Self::hash(val.name.as_ref().as_bytes())
            });
    }

    #[inline]
    fn find_idx_with_hash(&self, name: &str, hash: u64) -> Option<usize> {
        self.map
            .find(hash, |entry| entry.name.as_ref() == name)
            .map(|entry| entry.idx)
    }
}

impl CustomHash<&'static str> {
    pub(crate) fn from_symbols<L: ElfLayout>(
        symbols: &[ElfSymbol<L>],
        strtab: &ElfStringTable,
    ) -> Self {
        let mut hashtab = Self::with_capacity(symbols.len());

        for (idx, symbol) in symbols.iter().enumerate() {
            if symbol.symbol_type() == ElfSymbolType::FILE || symbol.is_undef() {
                continue;
            }

            let name = strtab.get_str(symbol.st_name() as usize);
            hashtab.insert_unique(name, idx);
        }

        hashtab
    }
}

impl<L: ElfLayout> SymbolHash<L> for CustomHash {
    fn lookup<'sym, H>(
        &self,
        table: SymbolTableView<'sym, L, H>,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&'sym ElfSymbol<L>> {
        self.lookup_idx(symbol, precompute)
            .map(|idx| table.symbol_idx(idx).0)
    }
}
