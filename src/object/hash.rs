//! Custom ELF hash table implementation for relocatable objects.

use crate::elf::{
    ElfHashTable, ElfLayout, ElfShdr, ElfStringTable, ElfSymbol, ElfSymbolType, HashTable,
    PreCompute, SymbolInfo, SymbolTable,
};
use core::hash::{Hash, Hasher};
use foldhash::{SharedSeed, fast::FoldHasher};
use hashbrown::HashTable as RawHashTable;

struct TableEntry {
    name: &'static str,
    idx: usize,
}

const HASHER: FoldHasher<'static> = FoldHasher::with_seed(0, SharedSeed::global_fixed());

pub(crate) struct CustomHash {
    map: RawHashTable<TableEntry>,
}

impl HashTable {
    pub(crate) fn from_shdr(symtab: &ElfShdr, strtab: &ElfStringTable) -> Self {
        HashTable::Custom(CustomHash::from_shdr(symtab, strtab))
    }
}

impl CustomHash {
    pub(crate) fn from_shdr(symtab: &ElfShdr, strtab: &ElfStringTable) -> Self {
        let symbols: &mut [ElfSymbol] = symtab.content_mut();
        let mut map = RawHashTable::with_capacity(symbols.len());

        for (idx, symbol) in symbols.iter_mut().enumerate() {
            if symbol.symbol_type() == ElfSymbolType::FILE {
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
}

impl ElfHashTable for CustomHash {
    fn hash(name: &[u8]) -> u64 {
        let mut hasher = HASHER.clone();
        name.hash(&mut hasher);
        hasher.finish()
    }

    fn count_syms(&self) -> usize {
        self.map.len()
    }

    fn lookup<'sym, L: ElfLayout>(
        table: &'sym SymbolTable<L>,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&'sym ElfSymbol<L>> {
        let HashTable::Custom(custom_hash) = &table.hashtab else {
            unreachable!("object symbol lookup requires custom hash table");
        };
        let name = symbol.name();
        let hash = if let Some(hash) = precompute.custom {
            hash
        } else {
            let hash = Self::hash(name.as_bytes());
            precompute.custom = Some(hash);
            hash
        };

        custom_hash
            .map
            .find(hash, |entry| entry.name == name)
            .map(|entry| table.symbol_idx(entry.idx).0)
    }
}
