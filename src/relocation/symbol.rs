use super::traits::RelocationArch;
use crate::{
    Result,
    elf::{ElfSymbol, ElfSymbolBind, ElfSymbolType, SymbolEntry},
    hint::unlikely,
    image::{Module, ModuleHandle, ModuleScope, SymbolLookup},
    logging,
    memory::{VmAddr, VmOffset},
    runtime::{CodeContext, CodeExecutor},
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap};
use core::ptr;
use spin::Mutex;

struct UniqueDef<Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    symbol: Arc<ElfSymbol<Arch::Layout>>,
    source: ModuleHandle<Arch, Tls>,
}

/// GNU unique symbol state shared by one linker context.
pub(crate) struct SymbolRegistry<Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    unique: Mutex<BTreeMap<Box<str>, UniqueDef<Arch, Tls>>>,
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> SymbolRegistry<Arch, Tls> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            unique: Mutex::new(BTreeMap::new()),
        }
    }

    fn resolve_unique<'lib>(
        &self,
        name: &str,
        symbol: &ElfSymbol<Arch::Layout>,
        source: &ModuleHandle<Arch, Tls>,
    ) -> SymDef<'lib, Arch, Tls> {
        let mut defs = self.unique.lock();
        if let Some(definition) = defs.get(name) {
            return SymDef::Unique {
                symbol: Arc::clone(&definition.symbol),
                source: definition.source.clone(),
            };
        }

        let symbol = Arc::new(symbol.clone());
        defs.insert(
            Box::from(name),
            UniqueDef {
                symbol: Arc::clone(&symbol),
                source: source.clone(),
            },
        );
        SymDef::Unique {
            symbol,
            source: source.clone(),
        }
    }

    fn register_copy(
        &self,
        name: &str,
        symbol: &ElfSymbol<Arch::Layout>,
        source: &ModuleHandle<Arch, Tls>,
    ) {
        let mut defs = self.unique.lock();
        if defs.contains_key(name) {
            return;
        }

        defs.insert(
            Box::from(name),
            UniqueDef {
                symbol: Arc::new(symbol.clone()),
                source: source.clone(),
            },
        );
    }
}

/// A symbol definition found during relocation.
///
/// Contains the symbol information and the module where it was found.
/// Used to compute the final address of a symbol.
pub enum SymDef<'lib, Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    Defined {
        symbol: &'lib ElfSymbol<Arch::Layout>,
        source: &'lib dyn Module<Arch, Tls>,
    },
    Unique {
        symbol: Arc<ElfSymbol<Arch::Layout>>,
        source: ModuleHandle<Arch, Tls>,
    },
    WeakUndef,
}

impl<'lib, Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> SymDef<'lib, Arch, Tls> {
    #[inline]
    pub(crate) fn defined(
        symbol: &'lib ElfSymbol<Arch::Layout>,
        source: &'lib dyn Module<Arch, Tls>,
    ) -> Self {
        Self::Defined { symbol, source }
    }

    #[inline]
    pub(crate) fn parts(&self) -> Option<(&ElfSymbol<Arch::Layout>, &dyn Module<Arch, Tls>)> {
        match self {
            Self::Defined { symbol, source } => Some((symbol, *source)),
            Self::Unique { symbol, source } => Some((symbol, source.as_dyn())),
            Self::WeakUndef => None,
        }
    }

    #[inline]
    pub(crate) const fn is_weak_undef(&self) -> bool {
        matches!(self, Self::WeakUndef)
    }

    /// Computes the symbol address (base + st_value).
    ///
    /// For regular symbols, returns base + st_value. For absolute symbols,
    /// returns st_value unchanged.
    /// For IFUNC symbols, returns the resolver address without executing it.
    /// For undefined weak symbols, returns null.
    pub(crate) fn addr(&self) -> VmAddr {
        let Some((symbol, source)) = self.parts() else {
            return VmAddr::null();
        };
        Self::defined_addr(symbol, source)
    }

    #[inline]
    fn defined_addr(symbol: &ElfSymbol<Arch::Layout>, source: &dyn Module<Arch, Tls>) -> VmAddr {
        if symbol.st_shndx().is_abs() {
            VmAddr::new(symbol.st_value())
        } else {
            source.memory().base() + VmOffset::new(symbol.st_value())
        }
    }

    #[inline]
    pub(crate) fn resolve(&self, executor: &dyn CodeExecutor<Arch>) -> Result<VmAddr> {
        let Some((symbol, source)) = self.parts() else {
            return Ok(VmAddr::null());
        };
        let addr = Self::defined_addr(symbol, source);
        if unlikely(symbol.symbol_type() == ElfSymbolType::GNU_IFUNC) {
            Self::resolve_ifunc(executor, source, addr)
        } else {
            Ok(addr)
        }
    }

    #[cold]
    #[inline(never)]
    fn resolve_ifunc(
        executor: &dyn CodeExecutor<Arch>,
        source: &dyn Module<Arch, Tls>,
        resolver: VmAddr,
    ) -> Result<VmAddr> {
        executor.resolve_ifunc(
            CodeContext::<Arch>::new(source.name(), source.memory()),
            resolver,
        )
    }
}

pub(crate) struct SymbolResolver<'lib, Source, Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    source: &'lib Source,
    scope: ModuleScope<Arch, Tls>,
    registry: Option<&'lib SymbolRegistry<Arch, Tls>>,
    symbolic: bool,
}

impl<'lib, Source, Arch, Tls> SymbolResolver<'lib, Source, Arch, Tls>
where
    Source: Module<Arch, Tls>,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    pub(crate) fn new(
        source: &'lib Source,
        scope: ModuleScope<Arch, Tls>,
        registry: Option<&'lib SymbolRegistry<Arch, Tls>>,
        symbolic: bool,
    ) -> Self {
        Self {
            source,
            scope,
            registry,
            symbolic,
        }
    }

    #[inline]
    pub(crate) const fn source(&self) -> &'lib Source {
        self.source
    }

    #[inline]
    pub(crate) const fn scope(&self) -> &ModuleScope<Arch, Tls> {
        &self.scope
    }

    #[inline]
    pub(crate) fn into_scope(self) -> ModuleScope<Arch, Tls> {
        self.scope
    }

    #[cold]
    #[inline(never)]
    fn source_handle(&self) -> Option<&ModuleHandle<Arch, Tls>> {
        self.scope.iter().find(|module| self.is_source(module))
    }

    #[inline]
    fn is_source(&self, module: &ModuleHandle<Arch, Tls>) -> bool {
        ptr::eq(module.memory(), self.source.memory())
    }

    fn lookup<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
        lookup: &mut SymbolLookup<'_>,
        source: &'find ModuleHandle<Arch, Tls>,
    ) -> Option<&'find ElfSymbol<Arch::Layout>> {
        let symbol = source
            .exports()
            .lookup(lookup)
            .filter(|symbol| symbol.is_exported())?;
        logging::trace!(
            "binding file [{}] to [{}]: symbol [{}]",
            self.source.name(),
            source.name(),
            entry.name()
        );
        Some(symbol)
    }

    fn find_in_scope<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
    ) -> Option<SymDef<'find, Arch, Tls>> {
        let mut lookup = SymbolLookup::from_info(entry.info().clone());
        self.scope.iter().find_map(|source| {
            let symbol = self.lookup(entry, &mut lookup, source)?;
            Some(self.bind(entry.name(), symbol, &**source, Some(source)))
        })
    }

    fn find_def<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
    ) -> Option<SymDef<'find, Arch, Tls>> {
        let sym = entry.symbol();
        let self_def =
            || (!sym.is_undef()).then(|| self.bind(entry.name(), sym, self.source, None));
        if unlikely(sym.binds_local()) {
            return self_def();
        }

        if self.symbolic {
            self_def().or_else(|| self.find_in_scope(entry))
        } else {
            self.find_in_scope(entry).or_else(self_def)
        }
    }

    fn bind<'find>(
        &self,
        name: &str,
        symbol: &'find ElfSymbol<Arch::Layout>,
        source: &'find dyn Module<Arch, Tls>,
        handle: Option<&'find ModuleHandle<Arch, Tls>>,
    ) -> SymDef<'find, Arch, Tls> {
        if unlikely(symbol.bind() == ElfSymbolBind::GNU_UNIQUE) {
            self.bind_unique(name, symbol, source, handle)
        } else {
            SymDef::defined(symbol, source)
        }
    }

    #[cold]
    #[inline(never)]
    fn bind_unique<'find>(
        &self,
        name: &str,
        symbol: &'find ElfSymbol<Arch::Layout>,
        source: &'find dyn Module<Arch, Tls>,
        handle: Option<&'find ModuleHandle<Arch, Tls>>,
    ) -> SymDef<'find, Arch, Tls> {
        let Some(registry) = &self.registry else {
            return SymDef::defined(symbol, source);
        };
        let Some(handle) = handle.or_else(|| self.source_handle()) else {
            debug_assert!(false, "linker scope must retain its relocation source");
            return SymDef::defined(symbol, source);
        };
        registry.resolve_unique(name, symbol, handle)
    }

    pub(crate) fn find<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
    ) -> Option<SymDef<'find, Arch, Tls>> {
        let sym = entry.symbol();
        self.find_def(entry).or_else(|| Self::weak_undef(sym))
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn find_copy<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
    ) -> Option<SymDef<'find, Arch, Tls>> {
        let mut lookup = SymbolLookup::from_info(entry.info().clone());
        let (symbol, source) = self
            .scope
            .iter()
            .filter(|source| !self.is_source(source))
            .find_map(|source| {
                self.lookup(entry, &mut lookup, source)
                    .map(|symbol| (symbol, source))
            })?;
        if symbol.bind() == ElfSymbolBind::GNU_UNIQUE
            && let Some(registry) = &self.registry
            && let Some(destination) = self.source_handle()
        {
            registry.register_copy(entry.name(), entry.symbol(), destination);
        }
        Some(SymDef::defined(symbol, &**source))
    }

    #[cold]
    fn weak_undef<'find>(sym: &'find ElfSymbol<Arch::Layout>) -> Option<SymDef<'find, Arch, Tls>> {
        if sym.is_weak() && sym.is_undef() {
            debug_assert_eq!(sym.st_value(), 0);
            Some(SymDef::WeakUndef)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SymbolRegistry, SymbolResolver};
    use crate::{
        arch::NativeArch,
        elf::{
            ElfSectionIndex, ElfSymbolBind, ElfSymbolType, ElfSymbolVisibility, NativeElfLayout,
            SymbolEntry, SymbolInfo,
        },
        image::{ModuleScope, ModuleScopeBuilder, SymbolExports, SyntheticModule, SyntheticSymbol},
        memory::VmAddr,
        runtime::DomainId,
    };

    fn symbol(module: &SyntheticModule<NativeArch>) -> SymbolEntry<'_, NativeElfLayout> {
        let symbol = SymbolExports::symbols(module)
            .first()
            .expect("test module must contain a symbol");
        SymbolEntry::new(symbol, SymbolInfo::from_str("value", None))
    }

    fn scope(modules: impl IntoIterator<Item = SyntheticModule<NativeArch>>) -> ModuleScope {
        let mut scope = ModuleScopeBuilder::new(DomainId::PROCESS);
        scope.extend(modules);
        scope.into_scope().expect("test scope must be valid")
    }

    #[test]
    fn symbol_visibility_controls_scope_lookup() {
        let source = SyntheticModule::new(
            "source",
            [SyntheticSymbol::function("value", 0x100usize as *const ())
                .with_other(ElfSymbolVisibility::PROTECTED.raw())],
        );
        let external = SyntheticModule::new(
            "external",
            [SyntheticSymbol::function("value", 0x200usize as *const ())],
        );
        let external_scope = scope([external]);
        let resolver = SymbolResolver::new(&source, external_scope, None, false);
        let def = resolver
            .find(&symbol(&source))
            .expect("protected definition must resolve locally");
        assert_eq!(def.addr(), VmAddr::new(0x100));

        let source = SyntheticModule::new(
            "source",
            [SyntheticSymbol::from_fields(
                "value",
                0,
                0,
                ElfSymbolBind::GLOBAL,
                ElfSymbolType::NOTYPE,
                ElfSymbolVisibility::DEFAULT.raw(),
                ElfSectionIndex::UNDEF,
                None,
            )],
        );
        let hidden = SyntheticModule::new(
            "hidden",
            [SyntheticSymbol::function("value", 0x200usize as *const ())
                .with_other(ElfSymbolVisibility::HIDDEN.raw())],
        );
        let visible = SyntheticModule::new(
            "visible",
            [SyntheticSymbol::function("value", 0x300usize as *const ())],
        );
        let scope = scope([hidden, visible]);
        let resolver = SymbolResolver::new(&source, scope.clone(), None, false);
        let def = resolver
            .find(&symbol(&source))
            .expect("lookup must continue past a hidden definition");
        assert_eq!(def.addr(), VmAddr::new(0x300));

        let hidden_ref = SyntheticModule::new(
            "source",
            [SyntheticSymbol::from_fields(
                "value",
                0,
                0,
                ElfSymbolBind::GLOBAL,
                ElfSymbolType::NOTYPE,
                ElfSymbolVisibility::HIDDEN.raw(),
                ElfSectionIndex::UNDEF,
                None,
            )],
        );
        assert!(
            SymbolResolver::new(&hidden_ref, scope, None, false)
                .find(&symbol(&hidden_ref))
                .is_none(),
            "hidden undefined reference must not resolve outside its module"
        );
    }

    #[test]
    fn gnu_unique_is_canonical_within_one_registry() {
        let source = SyntheticModule::new(
            "source",
            [SyntheticSymbol::from_fields(
                "value",
                0,
                0,
                ElfSymbolBind::GLOBAL,
                ElfSymbolType::NOTYPE,
                ElfSymbolVisibility::DEFAULT.raw(),
                ElfSectionIndex::UNDEF,
                None,
            )],
        );
        let unique = |name, value| {
            SyntheticModule::new(
                name,
                [SyntheticSymbol::from_fields(
                    "value",
                    value,
                    0,
                    ElfSymbolBind::GNU_UNIQUE,
                    ElfSymbolType::OBJECT,
                    ElfSymbolVisibility::DEFAULT.raw(),
                    ElfSectionIndex::ABS,
                    None,
                )],
            )
        };

        let registry = SymbolRegistry::new();
        let first = SymbolResolver::new(
            &source,
            scope([unique("first", 0x100)]),
            Some(&registry),
            false,
        );
        assert_eq!(
            first.find(&symbol(&source)).unwrap().addr(),
            VmAddr::new(0x100)
        );

        let second = SymbolResolver::new(
            &source,
            scope([unique("second", 0x200)]),
            Some(&registry),
            false,
        );
        assert_eq!(
            second.find(&symbol(&source)).unwrap().addr(),
            VmAddr::new(0x100)
        );

        let other_registry = SymbolRegistry::new();
        let other = SymbolResolver::new(
            &source,
            scope([unique("other", 0x300)]),
            Some(&other_registry),
            false,
        );
        assert_eq!(
            other.find(&symbol(&source)).unwrap().addr(),
            VmAddr::new(0x300)
        );
    }
}
