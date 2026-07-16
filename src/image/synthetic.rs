use super::{Module, ModuleHandle, SymbolExports, SymbolLookup};
use crate::{
    Result,
    arch::NativeArch,
    custom_error,
    elf::{ElfLayout, ElfSectionIndex, ElfSymbol, ElfSymbolBind, ElfSymbolType},
    memory::{ImageMemory, VmAddr},
    relocation::RelocationArch,
    sync::Arc,
    tls::{ModuleTls, TlsResolver},
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
    version: Option<SymbolVersion>,
    value: usize,
    size: usize,
    bind: ElfSymbolBind,
    symbol_type: ElfSymbolType,
    other: u8,
    section_index: ElfSectionIndex,
}

/// GNU symbol-version metadata for a [`SyntheticSymbol`].
#[derive(Clone, Debug)]
pub struct SymbolVersion {
    name: String,
    default: bool,
}

impl SymbolVersion {
    /// Creates symbol-version metadata.
    ///
    /// A default version corresponds to GNU `name@@version`; a non-default
    /// version corresponds to `name@version`.
    #[inline]
    pub fn new(name: impl Into<String>, default: bool) -> Self {
        Self {
            name: name.into(),
            default,
        }
    }

    /// Returns the version name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether this version satisfies an unversioned lookup.
    #[inline]
    pub const fn is_default(&self) -> bool {
        self.default
    }
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
            None,
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
            None,
        )
    }

    /// Creates a synthetic symbol with explicit ELF symbol fields.
    ///
    /// The synthetic module fills `st_name` when the symbol is inserted, so the
    /// caller controls every field except the internal name-table slot. Pass
    /// [`SymbolVersion`] to attach GNU symbol-version metadata.
    #[inline]
    pub fn from_fields(
        name: impl Into<String>,
        value: usize,
        size: usize,
        bind: ElfSymbolBind,
        symbol_type: ElfSymbolType,
        other: u8,
        section_index: ElfSectionIndex,
        version: Option<SymbolVersion>,
    ) -> Self {
        Self {
            name: name.into(),
            version,
            value,
            size,
            bind,
            symbol_type,
            other,
            section_index,
        }
    }

    /// Creates a synthetic symbol from an ELF symbol-table entry.
    ///
    /// `name` must be supplied separately because [`ElfSymbol::st_name`] is an
    /// index into the source image's string table. GNU version metadata likewise
    /// lives outside the ELF symbol-table entry.
    #[inline]
    pub fn from_elf<L: ElfLayout>(
        name: impl Into<String>,
        symbol: &ElfSymbol<L>,
        version: Option<SymbolVersion>,
    ) -> Self {
        Self::from_fields(
            name,
            symbol.st_value(),
            symbol.st_size(),
            symbol.bind(),
            symbol.symbol_type(),
            symbol.st_other(),
            symbol.st_shndx(),
            version,
        )
    }

    /// Exports this symbol with `version`.
    ///
    /// A default definition corresponds to GNU `name@@version` and may satisfy
    /// an unversioned lookup. A non-default definition corresponds to
    /// `name@version` and is available only to an exact versioned lookup.
    #[inline]
    pub fn with_version(mut self, version: impl Into<String>, default: bool) -> Self {
        self.version = Some(SymbolVersion::new(version, default));
        self
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
    index: BTreeMap<String, SymbolIndex>,
}

#[derive(Clone, Default)]
struct SymbolIndex {
    default: Option<usize>,
    versions: Vec<(SymbolVersion, usize)>,
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
            let _ = module.insert(symbol);
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

    /// Inserts one symbol, returning the definition it replaced.
    pub fn insert(&mut self, symbol: SyntheticSymbol) -> Option<SyntheticSymbol> {
        let name = symbol.name;
        let version = symbol.version;
        let entry = self.index.entry(name.clone()).or_default();
        let existing = match version.as_ref() {
            Some(version) => entry.versions.iter().find_map(|(entry, index)| {
                (entry.name == version.name).then(|| (*index, Some(entry.clone())))
            }),
            None => entry.default.map(|index| {
                let version = entry.versions.iter().find_map(|(version, version_index)| {
                    (*version_index == index && version.default).then(|| version.clone())
                });
                (index, version)
            }),
        };

        let (idx, previous) = if let Some((idx, previous_version)) = existing {
            let elf_symbol = ElfSymbol::synthetic(
                idx,
                symbol.value,
                symbol.size,
                symbol.bind,
                symbol.symbol_type,
                symbol.other,
                symbol.section_index,
            );
            let previous_name = core::mem::replace(&mut self.names[idx], name);
            let previous_symbol = core::mem::replace(&mut self.symbols[idx], elf_symbol);
            let previous =
                SyntheticSymbol::from_elf(previous_name, &previous_symbol, previous_version);
            (idx, Some(previous))
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
            self.names.push(name);
            self.symbols.push(elf_symbol);
            (idx, None)
        };

        match version {
            Some(version) => {
                let was_default = entry
                    .versions
                    .iter()
                    .position(|(entry, _)| entry.name == version.name)
                    .map(|position| entry.versions.remove(position).0.default)
                    .unwrap_or(false);
                if version.default {
                    for (entry, _) in &mut entry.versions {
                        entry.default = false;
                    }
                    entry.default = Some(idx);
                } else if was_default && entry.default == Some(idx) {
                    entry.default = None;
                }
                entry.versions.push((version, idx));
            }
            None => {
                if let Some(position) = entry
                    .versions
                    .iter()
                    .position(|(version, version_index)| *version_index == idx && version.default)
                {
                    entry.versions.remove(position);
                }
                entry.default = Some(idx);
            }
        }

        previous
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
        let entry = self.index.get(lookup.name())?;
        let idx = match lookup.version_name() {
            Some(version) => entry
                .versions
                .iter()
                .find_map(|(entry, index)| (entry.name == version).then_some(*index))?,
            None => entry.default?,
        };
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

    #[cfg(feature = "version")]
    #[test]
    fn synthetic_module_uses_one_default_symbol() {
        let mut module = SyntheticModule::<NativeArch>::new(
            "__versions",
            [SyntheticSymbol::function("entry", 0x1000usize as *const ())],
        );
        assert!(
            module
                .insert(SyntheticSymbol::from_fields(
                    "entry",
                    0x2000,
                    0,
                    ElfSymbolBind::GLOBAL,
                    ElfSymbolType::FUNC,
                    0,
                    ElfSectionIndex::ABS,
                    Some(SymbolVersion::new("VER_1", false)),
                ))
                .is_none()
        );

        let mut lookup = SymbolLookup::new("entry");
        assert_eq!(module.lookup(&mut lookup).unwrap().st_value(), 0x1000);

        let mut lookup = SymbolLookup::with_version("entry", "VER_1");
        assert_eq!(module.lookup(&mut lookup).unwrap().st_value(), 0x2000);

        assert!(
            module
                .insert(
                    SyntheticSymbol::function("entry", 0x3000usize as *const ())
                        .with_version("VER_2", true),
                )
                .is_none()
        );

        let mut lookup = SymbolLookup::new("entry");
        assert_eq!(module.lookup(&mut lookup).unwrap().st_value(), 0x3000);

        let mut lookup = SymbolLookup::with_version("entry", "VER_2");
        assert_eq!(module.lookup(&mut lookup).unwrap().st_value(), 0x3000);

        let previous = module
            .insert(
                SyntheticSymbol::function("entry", 0x4000usize as *const ())
                    .with_version("VER_2", true),
            )
            .unwrap();
        assert_eq!(previous.value, 0x3000);
        assert_eq!(previous.version.unwrap().name(), "VER_2");

        let previous = module
            .insert(SyntheticSymbol::function("entry", 0x5000usize as *const ()))
            .unwrap();
        assert_eq!(previous.value, 0x4000);
        assert_eq!(previous.version.unwrap().name(), "VER_2");

        let mut lookup = SymbolLookup::new("entry");
        assert_eq!(module.lookup(&mut lookup).unwrap().st_value(), 0x5000);

        let mut lookup = SymbolLookup::with_version("entry", "VER_2");
        assert!(module.lookup(&mut lookup).is_none());
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
                None,
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
