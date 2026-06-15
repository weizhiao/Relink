use crate::{
    elf::{ElfLayout, ElfSymbol, PreCompute, SymbolInfo},
    image::SymbolExports,
    object::CustomHash,
    relocation::RelocationArch,
};
use alloc::{string::String, vec::Vec};

/// Runtime symbol exports for a relocated object.
///
/// Unlike the relocation `.symtab`, this table owns symbol names and entries, so
/// it can outlive init-only section metadata.
pub(crate) struct ObjectExports<L: ElfLayout> {
    hashtab: CustomHash<String>,
    symbols: Vec<ElfSymbol<L>>,
}

impl<L: ElfLayout> ObjectExports<L> {
    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
            hashtab: CustomHash::with_capacity(0),
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
        self.symbols.push(symbol);
        self.hashtab.insert_unique(name, idx);
    }

    #[inline]
    pub(crate) fn symbols(&self) -> &[ElfSymbol<L>] {
        &self.symbols
    }

    #[inline]
    pub(crate) fn lookup(
        &self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&ElfSymbol<L>> {
        self.hashtab
            .lookup_idx(symbol, precompute)
            .map(|idx| &self.symbols[idx])
    }
}

impl<Arch: RelocationArch> SymbolExports<Arch> for ObjectExports<Arch::Layout> {
    #[inline]
    fn symbols(&self) -> &[ElfSymbol<Arch::Layout>] {
        self.symbols()
    }

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
        assert_eq!(
            <ObjectExports<NativeElfLayout> as SymbolExports<crate::arch::NativeArch>>::symbols(
                &exports
            )
            .len(),
            1
        );
    }
}
