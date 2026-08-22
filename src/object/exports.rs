use crate::{
    elf::{ElfLayout, ElfSymbol},
    image::{SymbolExports, SymbolLookup},
    object::CustomHash,
    sync::{Arc, OnceCell},
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

pub(crate) struct ObjectExportsCell<L: ElfLayout> {
    exports: OnceCell<Arc<dyn SymbolExports<L>>>,
}

impl<L: ElfLayout> ObjectExportsCell<L> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            exports: OnceCell::new(),
        }
    }

    #[inline]
    pub(crate) fn set(&self, exports: Arc<dyn SymbolExports<L>>) {
        assert!(
            self.exports.set(exports).is_ok(),
            "object exports must be installed only once",
        );
    }

    #[inline]
    fn get(&self) -> &dyn SymbolExports<L> {
        self.exports
            .get()
            .expect("object exports must be installed before lookup")
            .as_ref()
    }
}

impl<L: ElfLayout> SymbolExports<L> for ObjectExportsCell<L> {
    #[inline]
    fn for_each(&self, visitor: &mut dyn FnMut(&ElfSymbol<L>)) {
        self.get().for_each(visitor);
    }

    #[inline]
    fn symbol_name<'exports>(&'exports self, symbol: &ElfSymbol<L>) -> Option<&'exports str> {
        self.get().symbol_name(symbol)
    }

    #[inline]
    fn lookup<'exports>(
        &'exports self,
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'exports ElfSymbol<L>> {
        self.get().lookup(lookup)
    }
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
    fn for_each(&self, visitor: &mut dyn FnMut(&ElfSymbol<L>)) {
        self.symbols.iter().for_each(visitor);
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
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'exports ElfSymbol<L>> {
        self.hashtab
            .lookup_idx(lookup)
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
            0,
            0x1000,
            0,
            ElfSymbolBind::WEAK,
            ElfSymbolType::FUNC,
            0,
            ElfSectionIndex::ABS,
        );
        let strong = ElfSymbol::synthetic(
            0,
            0x2000,
            0,
            ElfSymbolBind::GLOBAL,
            ElfSymbolType::FUNC,
            0,
            ElfSectionIndex::ABS,
        );

        exports.insert("symbol", weak);
        exports.insert("symbol", strong);

        let mut lookup = SymbolLookup::new("symbol");
        let resolved = <ObjectExports<NativeElfLayout> as SymbolExports<NativeElfLayout>>::lookup(
            &exports,
            &mut lookup,
        )
        .expect("symbol should resolve");

        assert_eq!(resolved.st_value(), 0x2000);
        assert_eq!(
            <ObjectExports<NativeElfLayout> as SymbolExports<NativeElfLayout>>::symbol_name(
                &exports, resolved
            ),
            Some("symbol"),
        );
        let mut count = 0;
        exports.for_each(&mut |_| count += 1);
        assert_eq!(count, 1);
    }
}
