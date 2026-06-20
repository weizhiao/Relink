use super::{Module, ModuleHandle, SymbolExports};
use crate::{
    Result,
    arch::NativeArch,
    custom_error,
    elf::{ElfSectionIndex, ElfSymbol, ElfSymbolBind, ElfSymbolType, PreCompute, SymbolInfo},
    memory::{ImageMemory, VmAddr},
    relocation::RelocationArch,
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::ptr::NonNull;

/// One synthetic symbol exported by a [`SyntheticModule`].
///
/// Synthetic symbols are useful for host callbacks, native bridge wrappers,
/// and virtual replacement libraries where a symbol should resolve to a known
/// runtime address without loading another ELF image.
#[derive(Clone)]
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

struct SyntheticMemory;

static SYNTHETIC_MEMORY: SyntheticMemory = SyntheticMemory;

impl ImageMemory for SyntheticMemory {
    #[inline]
    fn base(&self) -> VmAddr {
        VmAddr::null()
    }

    #[inline]
    fn host_ptr(&self, _addr: VmAddr) -> Option<NonNull<u8>> {
        None
    }

    #[inline]
    fn host_ptr_range(&self, _addr: VmAddr, _len: usize) -> Option<NonNull<u8>> {
        None
    }

    #[inline]
    fn read_bytes(&self, _addr: VmAddr, _dst: &mut [u8]) -> Result<()> {
        Err(custom_error(
            "synthetic modules do not expose readable image bytes",
        ))
    }

    #[inline]
    fn write_bytes(&self, _addr: VmAddr, _src: &[u8]) -> Result<()> {
        Err(custom_error(
            "synthetic modules do not expose writable image bytes",
        ))
    }
}

/// A [`Module`] backed by a synthetic table of absolute symbols.
///
/// The module owns stable synthetic ELF symbols, so it can be retained in a
/// [`ModuleScope`](crate::image::ModuleScope) without borrowing callback-owned
/// symbol metadata.
pub struct SyntheticModule<Arch: RelocationArch = NativeArch> {
    name: String,
    names: Vec<String>,
    symbols: Vec<ElfSymbol<Arch::Layout>>,
    index: BTreeMap<String, usize>,
}

impl<Arch: RelocationArch> Clone for SyntheticModule<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            names: self.names.clone(),
            symbols: self.symbols.clone(),
            index: self.index.clone(),
        }
    }
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
            names: Vec::new(),
            symbols: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    /// Inserts or replaces one symbol.
    pub fn insert(&mut self, symbol: SyntheticSymbol) {
        let name = symbol.name;
        let elf_symbol = ElfSymbol::synthetic(
            symbol.value,
            symbol.size,
            symbol.bind,
            symbol.symbol_type,
            ElfSectionIndex::ABS,
        );

        if let Some(idx) = self.index.get(name.as_str()).copied() {
            self.names[idx] = name;
            self.symbols[idx] = elf_symbol;
        } else {
            let idx = self.symbols.len();
            self.index.insert(name.clone(), idx);
            self.names.push(name);
            self.symbols.push(elf_symbol);
        }
    }

    /// Returns whether this module exports a synthetic symbol with `name`.
    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        self.index.contains_key(name)
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
    fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
        self
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        &SYNTHETIC_MEMORY
    }
}

impl<Arch> SymbolExports<Arch::Layout> for SyntheticModule<Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    fn symbols(&self) -> &[ElfSymbol<Arch::Layout>] {
        &self.symbols
    }

    #[inline]
    fn symbol_name<'exports>(
        &'exports self,
        symbol: &ElfSymbol<Arch::Layout>,
    ) -> Option<&'exports str> {
        self.symbols
            .iter()
            .position(|entry| core::ptr::eq(entry, symbol))
            .map(|idx| self.names[idx].as_str())
    }

    #[inline]
    fn lookup<'exports>(
        &'exports self,
        symbol: &SymbolInfo<'_>,
        _precompute: &mut PreCompute,
    ) -> Option<&'exports ElfSymbol<Arch::Layout>> {
        let idx = self.index.get(symbol.name()).copied()?;
        Some(&self.symbols[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::ModuleScopeBuilder;

    #[test]
    fn synthetic_module_resolves_absolute_symbols_from_scope() {
        let module = SyntheticModule::<NativeArch>::new(
            "__bridge",
            [SyntheticSymbol::function(
                "host_double",
                0x1234usize as *const (),
            )],
        );
        let mut scope = ModuleScopeBuilder::new();
        scope.extend([module]);
        let scope = scope.into_scope();
        let info = SymbolInfo::from_str("host_double", None);
        let mut precompute = info.precompute();

        let module = scope
            .iter()
            .find(|module| module.name() == "__bridge")
            .expect("synthetic module should be retained in scope");
        let symbol = module
            .exports()
            .lookup(&info, &mut precompute)
            .expect("synthetic symbol should resolve");

        assert_eq!(symbol.st_value(), 0x1234);
        assert_eq!(symbol.st_size(), 0);
        assert_eq!(symbol.bind(), ElfSymbolBind::GLOBAL);
        assert_eq!(symbol.symbol_type(), ElfSymbolType::FUNC);
        assert!(symbol.st_shndx().is_abs());
        assert_eq!(module.exports().symbol_name(symbol), Some("host_double"));
        assert_eq!(module.exports().symbols().len(), 1);
    }
}
