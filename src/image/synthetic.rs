use super::{Module, ModuleHandle, ModuleTls, SymbolExports, SymbolLookup};
use crate::{
    Result,
    arch::NativeArch,
    custom_error,
    elf::{ElfSectionIndex, ElfSymbol, ElfSymbolBind, ElfSymbolType},
    memory::{ImageMemory, VmAddr},
    relocation::RelocationArch,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use core::ptr::NonNull;

/// One synthetic symbol exported by a [`SyntheticModule`].
///
/// Synthetic symbols are useful for host callbacks, native bridge wrappers,
/// and virtual replacement libraries where a symbol should resolve to a known
/// runtime address without loading another ELF image.
#[derive(Clone, Debug)]
pub struct SyntheticSymbol {
    name: String,
    value: usize,
    size: usize,
    bind: ElfSymbolBind,
    symbol_type: ElfSymbolType,
    other: u8,
    section_index: ElfSectionIndex,
}

impl SyntheticSymbol {
    /// Creates a function symbol backed by an absolute runtime address.
    #[inline]
    pub fn function(name: impl Into<String>, value: *const ()) -> Self {
        Self::from_fields(
            name,
            value as usize,
            0,
            ElfSymbolBind::GLOBAL,
            ElfSymbolType::FUNC,
            0,
            ElfSectionIndex::ABS,
        )
    }

    /// Creates an object symbol backed by an absolute runtime address.
    #[inline]
    pub fn object(name: impl Into<String>, value: *const (), size: usize) -> Self {
        Self::from_fields(
            name,
            value as usize,
            size,
            ElfSymbolBind::GLOBAL,
            ElfSymbolType::OBJECT,
            0,
            ElfSectionIndex::ABS,
        )
    }

    /// Creates a synthetic symbol with explicit ELF symbol fields.
    ///
    /// The synthetic module fills `st_name` when the symbol is inserted, so the
    /// caller controls every field except the internal name-table slot.
    #[inline]
    pub fn from_fields(
        name: impl Into<String>,
        value: usize,
        size: usize,
        bind: ElfSymbolBind,
        symbol_type: ElfSymbolType,
        other: u8,
        section_index: ElfSectionIndex,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            size,
            bind,
            symbol_type,
            other,
            section_index,
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

    /// Sets the ELF `st_other` value.
    #[inline]
    pub fn with_other(mut self, other: u8) -> Self {
        self.other = other;
        self
    }

    /// Sets the ELF section index used by the synthetic symbol.
    ///
    /// Function and object symbols default to [`ElfSectionIndex::ABS`] because
    /// they normally carry an already-resolved runtime address. TLS and
    /// module-relative symbols can override this with their real section index.
    #[inline]
    pub fn with_section(mut self, section_index: ElfSectionIndex) -> Self {
        self.section_index = section_index;
        self
    }
}

#[derive(Clone, Copy)]
struct UnmappedImageMemory {
    base: VmAddr,
}

impl Default for UnmappedImageMemory {
    #[inline]
    fn default() -> Self {
        Self {
            base: VmAddr::null(),
        }
    }
}

impl ImageMemory for UnmappedImageMemory {
    #[inline]
    fn base(&self) -> VmAddr {
        self.base
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
    fn read_bytes(&self, _addr: VmAddr, dst: &mut [u8]) -> Result<()> {
        if dst.is_empty() {
            return Ok(());
        }

        Err(custom_error(
            "synthetic modules do not expose readable image bytes",
        ))
    }

    #[inline]
    fn write_bytes(&self, _addr: VmAddr, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Ok(());
        }

        Err(custom_error(
            "synthetic modules do not expose writable image bytes",
        ))
    }
}

#[inline]
fn image_memory<M>(memory: M) -> Arc<dyn ImageMemory>
where
    M: ImageMemory + 'static,
{
    Arc::from(Box::new(memory) as Box<dyn ImageMemory>)
}

/// A [`Module`] backed by a synthetic table of absolute symbols.
///
/// The module owns stable synthetic ELF symbols, so it can be retained in a
/// [`ModuleScope`](crate::image::ModuleScope) without borrowing callback-owned
/// symbol metadata.
pub struct SyntheticModule<Arch: RelocationArch = NativeArch, D = ()> {
    name: String,
    memory: Arc<dyn ImageMemory>,
    tls: ModuleTls,
    user_data: D,
    names: Vec<String>,
    symbols: Vec<ElfSymbol<Arch::Layout>>,
    index: BTreeMap<String, usize>,
}

impl<Arch: RelocationArch, D: Clone> Clone for SyntheticModule<Arch, D> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            memory: self.memory.clone(),
            tls: self.tls,
            user_data: self.user_data.clone(),
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
            memory: image_memory(UnmappedImageMemory::default()),
            tls: ModuleTls::NONE,
            user_data: (),
            names: Vec::new(),
            symbols: Vec::new(),
            index: BTreeMap::new(),
        }
    }
}

impl<Arch: RelocationArch, D> SyntheticModule<Arch, D> {
    /// Replaces the user data associated with this synthetic module.
    #[inline]
    pub fn with_user_data<NewD>(self, user_data: NewD) -> SyntheticModule<Arch, NewD> {
        SyntheticModule {
            name: self.name,
            memory: self.memory,
            tls: self.tls,
            user_data,
            names: self.names,
            symbols: self.symbols,
            index: self.index,
        }
    }

    /// Returns immutable user data for this synthetic module.
    #[inline]
    pub const fn user_data(&self) -> &D {
        &self.user_data
    }

    /// Returns mutable user data for this synthetic module.
    #[inline]
    pub fn user_data_mut(&mut self) -> &mut D {
        &mut self.user_data
    }

    /// Uses a real image-memory backend for this synthetic module.
    ///
    /// This is required when synthetic symbols may be used as byte sources, such
    /// as for COPY relocations against synthetic object symbols.
    #[inline]
    pub fn with_memory<M>(mut self, memory: M) -> Self
    where
        M: ImageMemory + 'static,
    {
        self.memory = image_memory(memory);
        self
    }

    /// Sets TLS metadata exposed by this synthetic module.
    #[inline]
    pub fn with_tls(mut self, tls: ModuleTls) -> Self {
        self.tls = tls;
        self
    }

    /// Inserts or replaces one symbol.
    pub fn insert(&mut self, symbol: SyntheticSymbol) {
        let name = symbol.name;

        if let Some(idx) = self.index.get(name.as_str()).copied() {
            let elf_symbol = ElfSymbol::synthetic(
                idx,
                symbol.value,
                symbol.size,
                symbol.bind,
                symbol.symbol_type,
                symbol.other,
                symbol.section_index,
            );
            self.names[idx] = name;
            self.symbols[idx] = elf_symbol;
        } else {
            let idx = self.symbols.len();
            let elf_symbol = ElfSymbol::synthetic(
                idx,
                symbol.value,
                symbol.size,
                symbol.bind,
                symbol.symbol_type,
                symbol.other,
                symbol.section_index,
            );
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

impl<Arch, D, Tls> From<SyntheticModule<Arch, D>> for ModuleHandle<Arch, Tls>
where
    Arch: RelocationArch,
    D: Send + Sync + 'static,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn from(module: SyntheticModule<Arch, D>) -> Self {
        Self::new(module)
    }
}

impl<Arch, D, Tls> Module<Arch, Tls> for SyntheticModule<Arch, D>
where
    Arch: RelocationArch,
    D: Send + Sync + 'static,
    Tls: TlsResolver<Arch> + 'static,
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
        &*self.memory
    }

    #[inline]
    fn tls(&self) -> ModuleTls {
        self.tls
    }
}

impl<Arch, D> SymbolExports<Arch::Layout> for SyntheticModule<Arch, D>
where
    Arch: RelocationArch,
    D: Send + Sync,
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
        self.names.get(symbol.st_name()).map(String::as_str)
    }

    #[inline]
    fn lookup<'exports>(
        &'exports self,
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'exports ElfSymbol<Arch::Layout>> {
        let idx = self.index.get(lookup.name()).copied()?;
        Some(&self.symbols[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        image::ModuleScopeBuilder,
        memory::{MappedRegion, VmOffset},
        segment::ElfSegments,
        tls::{TlsModuleId, TlsTpOffset},
    };

    #[test]
    fn synthetic_module_resolves_absolute_symbols_from_scope() {
        let module = SyntheticModule::<NativeArch>::new(
            "__bridge",
            [SyntheticSymbol::function(
                "host_double",
                0x1234usize as *const (),
            )],
        );
        assert_eq!(
            <SyntheticModule<NativeArch> as Module<NativeArch, ()>>::memory(&module).base(),
            VmAddr::null()
        );

        let mut scope = ModuleScopeBuilder::<NativeArch>::new();
        scope.extend([module]);
        let scope = scope.into_scope();
        let mut lookup = SymbolLookup::new("host_double");

        let module = scope
            .iter()
            .find(|module| module.name() == "__bridge")
            .expect("synthetic module should be retained in scope");
        assert_eq!(module.memory().base(), VmAddr::null());
        let symbol = module
            .exports()
            .lookup(&mut lookup)
            .expect("synthetic symbol should resolve");

        assert_eq!(symbol.st_value(), 0x1234);
        assert_eq!(symbol.st_size(), 0);
        assert_eq!(symbol.bind(), ElfSymbolBind::GLOBAL);
        assert_eq!(symbol.symbol_type(), ElfSymbolType::FUNC);
        assert!(symbol.st_shndx().is_abs());
        assert_eq!(module.exports().symbol_name(symbol), Some("host_double"));
        assert_eq!(module.exports().symbols().len(), 1);
    }

    #[test]
    fn synthetic_symbol_can_use_non_absolute_section() {
        let module = SyntheticModule::<NativeArch>::new(
            "__tls",
            [SyntheticSymbol::from_fields(
                "tls_slot",
                0x20,
                8,
                ElfSymbolBind::WEAK,
                ElfSymbolType::TLS,
                3,
                ElfSectionIndex::new(1),
            )],
        );
        let mut scope = ModuleScopeBuilder::<NativeArch>::new();
        scope.extend([module]);
        let scope = scope.into_scope();
        let mut lookup = SymbolLookup::new("tls_slot");

        let module = scope
            .iter()
            .find(|module| module.name() == "__tls")
            .expect("synthetic module should be retained in scope");
        let symbol = module
            .exports()
            .lookup(&mut lookup)
            .expect("synthetic TLS symbol should resolve");

        assert_eq!(symbol.st_value(), 0x20);
        assert_eq!(symbol.st_size(), 8);
        assert_eq!(symbol.bind(), ElfSymbolBind::WEAK);
        assert_eq!(symbol.symbol_type(), ElfSymbolType::TLS);
        assert_eq!(symbol.st_other(), 3);
        assert_eq!(symbol.st_shndx(), ElfSectionIndex::new(1));
    }

    #[test]
    fn synthetic_module_can_carry_tls_metadata() {
        let tls = ModuleTls::Static {
            mod_id: TlsModuleId::new(7),
            tp_offset: TlsTpOffset::new(-0x80),
        };
        let module = SyntheticModule::<NativeArch>::empty("__tls").with_tls(tls);

        assert_eq!(
            <SyntheticModule<NativeArch> as Module<NativeArch, ()>>::tls(&module),
            tls
        );
    }

    #[test]
    fn synthetic_module_can_carry_user_data() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct SyntheticData {
            tag: usize,
        }

        let mut module =
            SyntheticModule::<NativeArch>::empty("__meta").with_user_data(SyntheticData { tag: 7 });

        assert_eq!(module.user_data().tag, 7);
        module.user_data_mut().tag = 11;
        assert_eq!(module.clone().user_data(), &SyntheticData { tag: 11 });
    }

    #[test]
    fn synthetic_module_can_delegate_image_memory() {
        let bytes = Box::leak(Box::new([1u8, 2, 3, 4]));
        let region =
            MappedRegion::local_alias_no_unmap(bytes.as_ptr().cast_mut().cast(), bytes.len());
        let base = VmAddr::from_ptr(bytes.as_ptr());
        let memory = ElfSegments::new(region, base, VmOffset::new(0));
        let module = SyntheticModule::<NativeArch>::empty("__data").with_memory(memory);
        let memory = <SyntheticModule<NativeArch> as Module<NativeArch, ()>>::memory(&module);
        let mut out = [0u8; 2];

        memory
            .read_bytes(base + VmOffset::new(1), &mut out)
            .expect("synthetic module should delegate readable image memory");

        assert_eq!(memory.base(), base);
        assert_eq!(out, [2, 3]);
    }
}
