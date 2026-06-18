use crate::{
    elf::{ElfLayout, ElfSymbol, PreCompute, SymbolInfo},
    image::SymbolExports,
    object::CustomHash,
};
use alloc::{string::String, vec::Vec};

/// Runtime symbol exports for a relocated object.
///
/// Unlike the relocation `.symtab`, this table owns symbol names and entries, so
/// it can outlive init-only section metadata.
pub(crate) struct ObjectExports<L: ElfLayout> {
    hashtab: CustomHash<String>,
    names: Vec<String>,
    symbols: Vec<ElfSymbol<L>>,
}

impl<L: ElfLayout> ObjectExports<L> {
    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
            hashtab: CustomHash::with_capacity(0),
            names: Vec::new(),
            symbols: Vec::new(),
        }
    }

    pub(crate) fn insert(&mut self, name: impl Into<String>, symbol: ElfSymbol<L>) {
        let name = name.into();
        if let Some(idx) = self.hashtab.find_idx(&name) {
            if self.symbols[idx].is_weak() && !symbol.is_weak() {
                self.symbols[idx] = symbol;
            }
            return;
        }

        let idx = self.symbols.len();
        self.names.push(name.clone());
        self.symbols.push(symbol);
        self.hashtab.insert_unique(name, idx);
    }
}

impl<L: ElfLayout> SymbolExports<L> for ObjectExports<L> {
    #[inline]
    fn symbols(&self) -> &[ElfSymbol<L>] {
        &self.symbols
    }

    #[inline]
    fn symbol_name<'exports>(&'exports self, symbol: &ElfSymbol<L>) -> Option<&'exports str> {
        self.symbols
            .iter()
            .position(|entry| core::ptr::eq(entry, symbol))
            .map(|idx| self.names[idx].as_str())
    }

    #[inline]
    fn lookup<'exports>(
        &'exports self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&'exports ElfSymbol<L>> {
        self.hashtab
            .lookup_idx(symbol, precompute)
            .map(|idx| &self.symbols[idx])
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
        let resolved = <ObjectExports<NativeElfLayout> as SymbolExports<NativeElfLayout>>::lookup(
            &exports,
            &info,
            &mut precompute,
        )
        .expect("symbol should resolve");

        assert_eq!(resolved.st_value(), 0x2000);
        assert_eq!(
            <ObjectExports<NativeElfLayout> as SymbolExports<NativeElfLayout>>::symbol_name(
                &exports, resolved
            ),
            Some("symbol"),
        );
        assert_eq!(
            <ObjectExports<NativeElfLayout> as SymbolExports<NativeElfLayout>>::symbols(&exports)
                .len(),
            1
        );
    }
}
