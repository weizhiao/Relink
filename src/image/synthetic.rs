use super::{Module, ModuleHandle};
use crate::{
    arch::NativeArch,
    elf::{
        ElfLayout, ElfSectionIndex, ElfSymbol, ElfSymbolBind, ElfSymbolType, PreCompute, SymbolInfo,
    },
    relocation::RelocationArch,
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::any::Any;

/// One synthetic symbol exported by a [`SyntheticModule`].
///
/// Synthetic symbols are useful for host callbacks, native bridge wrappers,
/// and virtual replacement libraries where a symbol should resolve to a known
/// runtime address without loading another ELF image.
pub struct SyntheticSymbol {
    name: String,
    value: usize,
    size: usize,
    bind: ElfSymbolBind,
    symbol_type: ElfSymbolType,
}

impl SyntheticSymbol {
    /// Creates a function symbol backed by an absolute runtime address.
    #[inline]
    pub fn function(name: impl Into<String>, value: *const ()) -> Self {
        Self::typed(name, value as usize, 0, ElfSymbolType::FUNC)
    }

    /// Creates an object symbol backed by an absolute runtime address.
    #[inline]
    pub fn object(name: impl Into<String>, value: *const (), size: usize) -> Self {
        Self::typed(name, value as usize, size, ElfSymbolType::OBJECT)
    }

    /// Creates a synthetic symbol with explicit ELF symbol type.
    #[inline]
    pub fn typed(
        name: impl Into<String>,
        value: usize,
        size: usize,
        symbol_type: ElfSymbolType,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            size,
            bind: ElfSymbolBind::GLOBAL,
            symbol_type,
        }
    }

    /// Sets the ELF symbol binding used by the synthetic symbol.
    #[inline]
    pub fn with_bind(mut self, bind: ElfSymbolBind) -> Self {
        self.bind = bind;
        self
    }

    /// Sets the ELF symbol size.
    #[inline]
    pub fn with_size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }
}

struct SymbolEntry<L: ElfLayout> {
    name: String,
    symbol: ElfSymbol<L>,
}

/// A [`Module`] backed by a synthetic table of absolute symbols.
///
/// The module owns stable synthetic ELF symbols, so it can be retained in a
/// [`ModuleScope`](crate::image::ModuleScope) without borrowing callback-owned
/// symbol metadata.
pub struct SyntheticModule<Arch: RelocationArch = NativeArch> {
    name: String,
    symbols: Vec<SymbolEntry<Arch::Layout>>,
    index: BTreeMap<String, usize>,
}

impl<Arch: RelocationArch> SyntheticModule<Arch> {
    /// Creates a module from an ordered list of synthetic symbols.
    pub fn new<I>(name: impl Into<String>, symbols: I) -> Self
    where
        I: IntoIterator<Item = SyntheticSymbol>,
    {
        let mut module = Self::empty(name);
        for symbol in symbols {
            module.insert(symbol);
        }
        module
    }

    /// Creates an empty synthetic module.
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            symbols: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    /// Inserts or replaces one symbol.
    pub fn insert(&mut self, symbol: SyntheticSymbol) {
        let entry = SymbolEntry {
            name: symbol.name,
            symbol: ElfSymbol::synthetic(
                symbol.value,
                symbol.size,
                symbol.bind,
                symbol.symbol_type,
                ElfSectionIndex::ABS,
            ),
        };

        if let Some(idx) = self.index.get(entry.name.as_str()).copied() {
            self.symbols[idx] = entry;
        } else {
            let idx = self.symbols.len();
            self.index.insert(entry.name.clone(), idx);
            self.symbols.push(entry);
        }
    }

    /// Returns the number of synthetic symbols.
    #[inline]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns whether this module contains no symbols.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

impl<Arch: RelocationArch> From<SyntheticModule<Arch>> for ModuleHandle<Arch> {
    #[inline]
    fn from(module: SyntheticModule<Arch>) -> Self {
        Self::new(module)
    }
}

impl<Arch> Module<Arch> for SyntheticModule<Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    fn lookup_symbol<'source>(
        &'source self,
        symbol: &SymbolInfo<'_>,
        _precompute: &mut PreCompute,
    ) -> Option<&'source ElfSymbol<Arch::Layout>> {
        let idx = self.index.get(symbol.name()).copied()?;
        Some(&self.symbols[idx].symbol)
    }

    #[inline]
    fn base_addr(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::ModuleScope;

    #[test]
    fn synthetic_module_resolves_absolute_symbols_from_scope() {
        let module = SyntheticModule::<NativeArch>::new(
            "__bridge",
            [SyntheticSymbol::function(
                "host_double",
                0x1234usize as *const (),
            )],
        );
        let scope = ModuleScope::new([module]);
        let info = SymbolInfo::from_str("host_double", None);
        let mut precompute = info.precompute();

        let symbol = scope.as_slice()[0]
            .lookup_symbol(&info, &mut precompute)
            .expect("synthetic symbol should resolve");

        assert_eq!(symbol.st_value(), 0x1234);
        assert_eq!(symbol.st_size(), 0);
        assert_eq!(symbol.bind(), ElfSymbolBind::GLOBAL);
        assert_eq!(symbol.symbol_type(), ElfSymbolType::FUNC);
        assert!(symbol.st_shndx().is_abs());
    }
}
