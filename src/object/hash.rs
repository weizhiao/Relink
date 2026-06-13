//! Custom ELF hash table implementation for relocatable objects.

use crate::elf::{
    ElfLayout, ElfStringTable, ElfSymbol, ElfSymbolType, PreCompute, SymbolHash, SymbolInfo,
    SymbolTableView,
};
use core::hash::{Hash, Hasher};
use foldhash::{SharedSeed, fast::FoldHasher};
use hashbrown::HashTable as RawHashTable;

struct TableEntry {
    name: &'static str,
    idx: usize,
}

const HASHER: FoldHasher<'static> = FoldHasher::with_seed(0, SharedSeed::global_fixed());

pub struct CustomHash {
    map: RawHashTable<TableEntry>,
}

impl CustomHash {
    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
            map: RawHashTable::new(),
        }
    }

    pub(crate) fn hash(name: &[u8]) -> u64 {
        let mut hasher = HASHER.clone();
        name.hash(&mut hasher);
        hasher.finish()
    }

    pub(crate) fn from_symbols<L: ElfLayout>(
        symbols: &[ElfSymbol<L>],
        strtab: &ElfStringTable,
    ) -> Self {
        let mut map = RawHashTable::with_capacity(symbols.len());

        for (idx, symbol) in symbols.iter().enumerate() {
            if symbol.symbol_type() == ElfSymbolType::FILE || symbol.is_undef() {
                continue;
            }

            let name = strtab.get_str(symbol.st_name() as usize);
            let hash = Self::hash(name.as_bytes());
            map.insert_unique(hash, TableEntry { name, idx }, |val| {
                Self::hash(val.name.as_bytes())
            });
        }

        Self { map }
    }

    #[inline]
    pub(crate) fn count_syms(&self) -> usize {
        self.map.len()
    }
}

impl<L: ElfLayout> SymbolHash<L> for CustomHash {
    fn lookup<'sym, H>(
        &self,
        table: SymbolTableView<'sym, L, H>,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&'sym ElfSymbol<L>> {
        let name = symbol.name();
        let hash = if let Some(hash) = precompute.custom {
            hash
        } else {
            let hash = Self::hash(name.as_bytes());
            precompute.custom = Some(hash);
            hash
        };

        self.map
            .find(hash, |entry| entry.name == name)
            .map(|entry| table.symbol_idx(entry.idx).0)
    }
}
