use crate::{
    elf::{ElfLayout, ElfSymbol, PreCompute, SymbolInfo, SymbolTableView},
    image::SymbolExports,
    relocation::RelocationArch,
};
use alloc::string::String;
use hashbrown::{HashMap, hash_map::Entry};

/// Runtime symbol exports for a relocated object.
///
/// Unlike the relocation `.symtab`, this table owns symbol names and entries, so
/// it can outlive init-only section metadata.
pub(crate) struct ObjectExports<L: ElfLayout> {
    symbols: HashMap<String, ElfSymbol<L>>,
}

impl<L: ElfLayout> Clone for ObjectExports<L> {
    fn clone(&self) -> Self {
        Self {
            symbols: self.symbols.clone(),
        }
    }
}

impl<L: ElfLayout> ObjectExports<L> {
    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
            symbols: HashMap::new(),
        }
    }

    pub(crate) fn from_symtab<H, F>(symtab: SymbolTableView<'_, L, H>, mut include: F) -> Self
    where
        F: FnMut(&ElfSymbol<L>) -> bool,
    {
        let mut exports = Self::empty();
        for idx in 0..symtab.symbols().len() {
            let (symbol, info) = symtab.symbol_idx(idx);
            if symbol.is_undef() || !symbol.is_ok_bind() || !symbol.is_ok_type() || !include(symbol)
            {
                continue;
            }

            exports.insert(info.name(), symbol.clone());
        }
        exports
    }

    pub(crate) fn insert(&mut self, name: impl Into<String>, symbol: ElfSymbol<L>) {
        match self.symbols.entry(name.into()) {
            Entry::Occupied(mut entry) => {
                if should_replace(entry.get(), &symbol) {
                    entry.insert(symbol);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(symbol);
            }
        }
    }

    #[inline]
    pub(crate) fn lookup(
        &self,
        symbol: &SymbolInfo<'_>,
        _precompute: &mut PreCompute,
    ) -> Option<&ElfSymbol<L>> {
        self.symbols.get(symbol.name())
    }
}

#[inline]
fn should_replace<L: ElfLayout>(existing: &ElfSymbol<L>, candidate: &ElfSymbol<L>) -> bool {
    existing.is_weak() && !candidate.is_weak()
}

impl<Arch: RelocationArch> SymbolExports<Arch> for ObjectExports<Arch::Layout> {
    #[inline]
    fn lookup<'exports>(
        &'exports self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&'exports ElfSymbol<Arch::Layout>> {
        self.lookup(symbol, precompute)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::{ElfSectionIndex, ElfSymbolBind, ElfSymbolType, NativeElfLayout};

    #[test]
    fn strong_export_replaces_weak_export() {
        let mut exports = ObjectExports::<NativeElfLayout>::empty();
        let weak = ElfSymbol::synthetic(
            0x1000,
            0,
            ElfSymbolBind::WEAK,
            ElfSymbolType::FUNC,
            ElfSectionIndex::ABS,
        );
        let strong = ElfSymbol::synthetic(
            0x2000,
            0,
            ElfSymbolBind::GLOBAL,
            ElfSymbolType::FUNC,
            ElfSectionIndex::ABS,
        );

        exports.insert("symbol", weak);
        exports.insert("symbol", strong);

        let info = SymbolInfo::from_str("symbol", None);
        let mut precompute = info.precompute();
        let resolved = exports
            .lookup(&info, &mut precompute)
            .expect("symbol should resolve");

        assert_eq!(resolved.st_value(), 0x2000);
    }
}
