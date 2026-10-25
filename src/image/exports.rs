//! Module exports and caller-owned symbol definitions.

use super::{SymbolLookup, SymbolName};
use crate::elf::{
    ElfLayout, ElfSectionIndex, ElfSymbol, ElfSymbolBind, ElfSymbolType, NativeElfLayout,
    SymbolTable,
};
#[cfg(feature = "object")]
use crate::sync::OnceCell;
use alloc::vec::Vec;
use core::ffi::CStr;
use hashbrown::HashTable;

/// A symbol exported by a [`super::SyntheticModule`], such as a host callback or variable.
/// Use a C string literal or [`SymbolName`] for its name.
#[derive(Clone, Debug)]
pub struct SyntheticSymbol {
    name: SymbolName,
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
    name: Vec<u8>,
    default: bool,
}

impl SymbolVersion {
    /// Creates symbol-version metadata.
    ///
    /// A default version corresponds to GNU `name@@version`; a non-default
    /// version corresponds to `name@version`.
    #[inline]
    pub fn new(name: impl AsRef<[u8]>, default: bool) -> Self {
        Self {
            name: name.as_ref().to_vec(),
            default,
        }
    }

    /// Returns the version name.
    #[inline]
    pub fn name(&self) -> &[u8] {
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
    pub fn function(name: impl Into<SymbolName>, value: *const ()) -> Self {
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
    pub fn object(name: impl Into<SymbolName>, value: *const (), size: usize) -> Self {
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

    /// Creates a TLS symbol whose value is an offset in this module's TLS block.
    #[inline]
    pub fn tls(name: impl Into<SymbolName>, offset: usize, size: usize) -> Self {
        Self::from_fields(
            name,
            offset,
            size,
            ElfSymbolBind::GLOBAL,
            ElfSymbolType::TLS,
            0,
            ElfSectionIndex::new(1),
            None,
        )
    }

    /// Creates a symbol with explicit ELF fields and optional GNU version metadata.
    /// The module assigns `st_name` when the symbol is inserted.
    #[inline]
    pub fn from_fields(
        name: impl Into<SymbolName>,
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
        name: impl Into<SymbolName>,
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
    pub fn with_version(mut self, version: impl AsRef<[u8]>, default: bool) -> Self {
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

/// Symbol exports shared by all module kinds.
///
/// Native ELF modules retain their existing symbol tables. Build caller-owned
/// symbols with [`SymbolMap`], then convert the map into an export table with
/// [`From::from`]. The public interface provides shared access for lookup.
pub struct ExportTable<L: ElfLayout = NativeElfLayout> {
    storage: ExportStorage<L>,
}

enum ExportStorage<L: ElfLayout> {
    Elf(SymbolTable<L>),
    Symbols(SymbolMap<L>),
    #[cfg(feature = "object")]
    Object(OnceCell<SymbolMap<L>>),
}

/// Caller-owned symbol definitions, indexed by name and optional GNU version.
///
/// Supports insertion through an exclusive borrow. Convert it into an
/// [`ExportTable`] to expose the symbols from a module.
pub struct SymbolMap<L: ElfLayout = NativeElfLayout> {
    names: Vec<SymbolName>,
    symbols: Vec<ElfSymbol<L>>,
    index: HashTable<IndexedName>,
    match_versions: bool,
}

impl<L: ElfLayout> From<SymbolMap<L>> for ExportTable<L> {
    fn from(symbols: SymbolMap<L>) -> Self {
        Self {
            storage: ExportStorage::Symbols(symbols),
        }
    }
}

impl<L: ElfLayout> ExportTable<L> {
    pub(super) fn symbols_mut(&mut self) -> &mut SymbolMap<L> {
        // SyntheticModule constructs this table from a SymbolMap and retains
        // exclusive access while accepting new symbol definitions.
        match &mut self.storage {
            ExportStorage::Symbols(symbols) => symbols,
            _ => unreachable!("only caller-owned export tables can be modified"),
        }
    }

    pub(crate) fn from_elf(symbols: SymbolTable<L>) -> Self {
        Self {
            storage: ExportStorage::Elf(symbols),
        }
    }

    /// Borrows the full dynamic table, including undefined symbols referenced
    /// by relocation indices. This is only used by dynamic ELF modules.
    pub(crate) fn elf_symbols(&self) -> &SymbolTable<L> {
        match &self.storage {
            ExportStorage::Elf(symbols) => symbols,
            _ => unreachable!("dynamic ELF symbols required"),
        }
    }

    #[inline]
    pub(super) fn symbols(&self) -> &SymbolMap<L> {
        match &self.storage {
            ExportStorage::Symbols(symbols) => symbols,
            #[cfg(feature = "object")]
            ExportStorage::Object(slot) => slot.get().expect("exports not yet installed"),
            ExportStorage::Elf(_) => unreachable!("symbol map required"),
        }
    }

    /// Looks up a symbol by name and optional version.
    #[inline]
    pub fn lookup(&self, lookup: &mut SymbolLookup<'_>) -> Option<&ElfSymbol<L>> {
        match &self.storage {
            ExportStorage::Elf(symbols) => symbols.lookup(lookup),
            _ => self.symbols().lookup(lookup),
        }
    }

    /// Visits symbols represented by this table.
    ///
    /// Native ELF tables may include entries that are not exported; use
    /// [`ElfSymbol::is_exported`] to check their eligibility.
    #[inline]
    pub fn for_each(&self, visitor: &mut dyn FnMut(&ElfSymbol<L>)) {
        match &self.storage {
            ExportStorage::Elf(symbols) => {
                symbols.hashtab.for_each(symbols.view(), visitor);
            }
            _ => self.symbols().for_each(visitor),
        }
    }

    /// Returns the name of a symbol from this export table.
    #[inline]
    pub fn symbol_name(&self, symbol: &ElfSymbol<L>) -> Option<&CStr> {
        match &self.storage {
            ExportStorage::Elf(symbols) => Some(symbols.strtab().get_cstr(symbol.st_name())),
            _ => self.symbols().symbol_name(symbol),
        }
    }
}

#[cfg(feature = "object")]
impl<L: ElfLayout> ExportTable<L> {
    pub(crate) fn pending_object() -> Self {
        Self {
            storage: ExportStorage::Object(OnceCell::new()),
        }
    }

    pub(crate) fn install_object(&self, symbols: SymbolMap<L>) {
        match &self.storage {
            ExportStorage::Object(slot) => {
                assert!(slot.set(symbols).is_ok(), "exports already installed");
            }
            _ => unreachable!("object exports required"),
        }
    }
}

struct IndexedName {
    hash: u64,
    name: SymbolName,
    symbols: SymbolIndex,
}

#[derive(Clone, Default)]
struct SymbolIndex {
    default: Option<usize>,
    versions: Vec<(Vec<u8>, usize)>,
}

impl<L: ElfLayout> SymbolMap<L> {
    /// Creates an empty symbol map.
    pub fn empty() -> Self {
        Self {
            names: Vec::new(),
            symbols: Vec::new(),
            index: HashTable::new(),
            match_versions: true,
        }
    }

    /// Collects symbols in insertion order.
    pub fn new(symbols: impl IntoIterator<Item = SyntheticSymbol>) -> Self {
        let mut map = Self::empty();
        for symbol in symbols {
            map.insert(symbol);
        }
        map
    }

    /// Returns the number of symbol definitions.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns whether the map contains no symbols.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Matches requests by name, regardless of their version requirement.
    #[cfg(feature = "object")]
    pub(crate) fn ignore_versions(&mut self) {
        self.match_versions = false;
    }

    /// Inserts one symbol, returning the definition it replaced.
    pub fn insert(&mut self, symbol: SyntheticSymbol) -> Option<SyntheticSymbol> {
        let hash = SymbolLookup::new(symbol.name.as_bytes()).index_hash();
        let entry = self
            .index
            .entry(hash, |entry| entry.name == symbol.name, |entry| entry.hash)
            .or_insert_with(|| IndexedName {
                hash,
                name: symbol.name,
                symbols: SymbolIndex::default(),
            })
            .into_mut();
        let name = entry.name.clone();
        let entry = &mut entry.symbols;
        let version = symbol.version;
        let existing = match version.as_ref() {
            Some(version) => entry.versions.iter().find_map(|(name, index)| {
                (*name == version.name).then(|| {
                    (
                        *index,
                        Some(SymbolVersion::new(name, entry.default == Some(*index))),
                    )
                })
            }),
            None => entry.default.map(|index| {
                let version = entry.versions.iter().find_map(|(name, version_index)| {
                    (*version_index == index).then(|| SymbolVersion::new(name, true))
                });
                (index, version)
            }),
        };

        let idx = existing
            .as_ref()
            .map_or(self.symbols.len(), |(index, _)| *index);
        let elf_symbol = ElfSymbol::synthetic(
            idx,
            symbol.value,
            symbol.size,
            symbol.bind,
            symbol.symbol_type,
            symbol.other,
            symbol.section_index,
        );
        let previous = if let Some((_, previous_version)) = existing {
            let previous_symbol = core::mem::replace(&mut self.symbols[idx], elf_symbol);
            let previous = SyntheticSymbol::from_elf(
                self.names[idx].clone(),
                &previous_symbol,
                previous_version,
            );
            Some(previous)
        } else {
            self.names.push(name);
            self.symbols.push(elf_symbol);
            None
        };

        entry.versions.retain(|(_, index)| *index != idx);
        match version {
            Some(version) => {
                if version.default {
                    entry.default = Some(idx);
                } else if entry.default == Some(idx) {
                    entry.default = None;
                }
                entry.versions.push((version.name, idx));
            }
            None => {
                entry.default = Some(idx);
            }
        }

        previous
    }

    /// Returns whether the table contains any definition with `name`.
    #[inline]
    pub fn contains(&self, name: impl AsRef<[u8]>) -> bool {
        let mut lookup = SymbolLookup::new(&name);
        self.index
            .find(lookup.index_hash(), |entry| {
                entry.name.as_bytes() == lookup.name()
            })
            .is_some()
    }

    /// Visits symbol definitions in insertion order.
    #[inline]
    pub fn for_each(&self, visitor: &mut dyn FnMut(&ElfSymbol<L>)) {
        self.symbols.iter().for_each(visitor);
    }

    /// Returns the name of a symbol from this map.
    #[inline]
    pub fn symbol_name<'exports>(&'exports self, symbol: &ElfSymbol<L>) -> Option<&'exports CStr> {
        self.names.get(symbol.st_name()).map(SymbolName::as_c_str)
    }

    /// Looks up a symbol by name and optional version.
    #[inline]
    pub fn lookup<'exports>(
        &'exports self,
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'exports ElfSymbol<L>> {
        let entry = &self
            .index
            .find(lookup.index_hash(), |entry| {
                entry.name.as_bytes() == lookup.name()
            })?
            .symbols;
        let idx = match lookup.version_name() {
            Some(version) if self.match_versions => entry
                .versions
                .iter()
                .find_map(|(name, index)| (name == version).then_some(*index))?,
            _ => entry.default?,
        };
        Some(&self.symbols[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_hash_collisions_keep_names_and_replacements_distinct() {
        // These names have the same GNU hash, including the absent third name.
        let names = [c"ab", c"bA", c"c "];
        let hash = SymbolLookup::new(names[0].to_bytes()).gnu_hash();
        for name in names {
            assert_eq!(SymbolLookup::new(name.to_bytes()).gnu_hash(), hash);
        }
        let mut module = SymbolMap::<NativeElfLayout>::empty();
        module.insert(SyntheticSymbol::function(
            names[0],
            0x1000usize as *const (),
        ));
        module.insert(SyntheticSymbol::function(
            names[1],
            0x2000usize as *const (),
        ));
        // Force table growth and verify that rehashing preserves all entries.
        for index in 0..128 {
            let name = alloc::ffi::CString::new(alloc::format!("extra_{index}")).unwrap();
            module.insert(SyntheticSymbol::function(
                name,
                (0x4000 + index) as *const (),
            ));
        }
        for index in 0..128 {
            let name = alloc::format!("extra_{index}");
            assert_eq!(
                module
                    .lookup(&mut SymbolLookup::new(&name))
                    .unwrap()
                    .st_value(),
                0x4000 + index
            );
        }
        assert!(module.contains(b"ab"));
        assert!(module.contains(b"bA"));
        assert!(!module.contains(b"c "));
        assert!(module.lookup(&mut SymbolLookup::new(b"c ")).is_none());
        let old = module
            .insert(SyntheticSymbol::function(
                names[0],
                0x3000usize as *const (),
            ))
            .unwrap();
        assert_eq!(old.value, 0x1000);
        for (name, address) in [(b"ab", 0x3000), (b"bA", 0x2000)] {
            assert_eq!(
                module
                    .lookup(&mut SymbolLookup::new(name))
                    .unwrap()
                    .st_value(),
                address
            );
        }
    }

    #[cfg(feature = "version")]
    #[test]
    fn synthetic_module_uses_one_default_symbol() {
        let mut module = SymbolMap::<NativeElfLayout>::new([SyntheticSymbol::function(
            c"entry",
            0x1000usize as *const (),
        )]);
        assert!(
            module
                .insert(SyntheticSymbol::from_fields(
                    c"entry",
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
                    SyntheticSymbol::function(c"entry", 0x3000usize as *const ())
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
                SyntheticSymbol::function(c"entry", 0x4000usize as *const ())
                    .with_version("VER_2", true),
            )
            .unwrap();
        assert_eq!(previous.value, 0x3000);
        assert_eq!(previous.version.unwrap().name(), b"VER_2");

        let previous = module
            .insert(SyntheticSymbol::function(
                c"entry",
                0x5000usize as *const (),
            ))
            .unwrap();
        assert_eq!(previous.value, 0x4000);
        assert_eq!(previous.version.unwrap().name(), b"VER_2");

        let mut lookup = SymbolLookup::new("entry");
        assert_eq!(module.lookup(&mut lookup).unwrap().st_value(), 0x5000);

        let mut lookup = SymbolLookup::with_version("entry", "VER_2");
        assert!(module.lookup(&mut lookup).is_none());
    }
}
