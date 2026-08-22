use super::traits::RelocationArch;
use crate::{
    Result,
    elf::{ElfSymbol, ElfSymbolBind, SymbolEntry},
    hint::unlikely,
    image::{LookupScope, Module, ModuleHandle, ModuleInstanceId, ModuleScope, SymbolLookup},
    logging,
    memory::VmAddr,
    sync::{Arc, Weak},
    tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap};
use spin::Mutex;

struct UniqueDef<Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    symbol: Arc<ElfSymbol<Arch::Layout>>,
    source: Weak<dyn Module<Arch, Tls>>,
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
        let (symbol, source) = if let Some((symbol, source)) =
            defs.get(name).and_then(|definition| {
                definition
                    .source
                    .upgrade()
                    .map(ModuleHandle::from_shared)
                    .map(|source| (Arc::clone(&definition.symbol), source))
            }) {
            (symbol, source)
        } else {
            let symbol = Arc::new(symbol.clone());
            defs.insert(
                Box::from(name),
                UniqueDef {
                    symbol: Arc::clone(&symbol),
                    source: source.downgrade(),
                },
            );
            (symbol, source.clone())
        };
        source.state().mark_nodelete();
        SymDef::Unique { symbol, source }
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
    pub(crate) fn definition(&self) -> Option<(&ElfSymbol<Arch::Layout>, &dyn Module<Arch, Tls>)> {
        match self {
            Self::Defined { symbol, source } => Some((symbol, *source)),
            Self::Unique { symbol, source } => Some((symbol, source.as_dyn())),
            Self::WeakUndef => None,
        }
    }

    #[inline]
    pub(crate) fn provider_id(&self) -> Option<ModuleInstanceId> {
        self.definition()
            .map(|(_, source)| source.state().instance_id())
    }

    #[inline]
    pub(crate) const fn is_weak_undef(&self) -> bool {
        matches!(self, Self::WeakUndef)
    }

    #[inline]
    pub(crate) fn resolve(&self) -> Result<VmAddr> {
        let Some((symbol, source)) = self.definition() else {
            return Ok(VmAddr::null());
        };
        source.resolve_symbol(symbol)
    }
}

pub(crate) struct SymbolResolver<'lib, Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    source: &'lib ModuleHandle<Arch, Tls>,
    scope: LookupScope<Arch, Tls>,
    global: Option<ModuleScope<Arch, Tls>>,
    registry: Option<&'lib SymbolRegistry<Arch, Tls>>,
    symbolic: bool,
}

impl<'lib, Arch, Tls> SymbolResolver<'lib, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    pub(crate) fn new(
        source: &'lib ModuleHandle<Arch, Tls>,
        scope: LookupScope<Arch, Tls>,
        global: Option<ModuleScope<Arch, Tls>>,
        registry: Option<&'lib SymbolRegistry<Arch, Tls>>,
        symbolic: bool,
    ) -> Self {
        Self {
            source,
            scope,
            global,
            registry,
            symbolic,
        }
    }

    #[inline]
    pub(crate) const fn scope(&self) -> &LookupScope<Arch, Tls> {
        &self.scope
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (LookupScope<Arch, Tls>, Option<ModuleScope<Arch, Tls>>) {
        (self.scope, self.global)
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

    fn lookup_in_scope<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
        mut accept: impl FnMut(&ModuleHandle<Arch, Tls>) -> bool,
    ) -> Option<(
        &'find ElfSymbol<Arch::Layout>,
        &'find ModuleHandle<Arch, Tls>,
    )> {
        let mut lookup = SymbolLookup::from_info(entry.info().clone());
        self.global
            .iter()
            .flat_map(ModuleScope::iter)
            .chain(self.scope.iter())
            .filter(|source| accept(source))
            .find_map(|source| {
                self.lookup(entry, &mut lookup, source)
                    .map(|symbol| (symbol, source))
            })
    }

    fn find_def<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
    ) -> Option<SymDef<'find, Arch, Tls>> {
        let sym = entry.symbol();
        let self_def = || (!sym.is_undef()).then(|| self.bind(entry.name(), sym, self.source));
        let scope_def = || {
            let (symbol, source) = self.lookup_in_scope(entry, |_| true)?;
            Some(self.bind(entry.name(), symbol, source))
        };
        if unlikely(sym.binds_local()) {
            return self_def();
        }

        if self.symbolic {
            self_def().or_else(scope_def)
        } else {
            scope_def().or_else(self_def)
        }
    }

    fn bind<'find>(
        &self,
        name: &str,
        symbol: &'find ElfSymbol<Arch::Layout>,
        source: &'find ModuleHandle<Arch, Tls>,
    ) -> SymDef<'find, Arch, Tls> {
        if unlikely(symbol.bind() == ElfSymbolBind::GNU_UNIQUE) {
            self.bind_unique(name, symbol, source)
        } else {
            SymDef::defined(symbol, source.as_dyn())
        }
    }

    #[cold]
    #[inline(never)]
    fn bind_unique<'find>(
        &self,
        name: &str,
        symbol: &'find ElfSymbol<Arch::Layout>,
        source: &'find ModuleHandle<Arch, Tls>,
    ) -> SymDef<'find, Arch, Tls> {
        if let Some(registry) = &self.registry {
            registry.resolve_unique(name, symbol, source)
        } else {
            source.state().mark_nodelete();
            SymDef::defined(symbol, source.as_dyn())
        }
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
        let source_id = self.source.source_id();
        let (symbol, source) =
            self.lookup_in_scope(entry, |source| source.source_id() != source_id)?;
        if symbol.bind() == ElfSymbolBind::GNU_UNIQUE
            && let Some(registry) = &self.registry
        {
            let _ = registry.resolve_unique(entry.name(), entry.symbol(), self.source);
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
            SymbolEntry, SymbolInfo, SymbolLookup,
        },
        image::{LookupScope, ModuleHandle, ModuleScope, SyntheticModule, SyntheticSymbol},
        memory::VmAddr,
        runtime::DomainId,
    };

    fn symbol(module: &ModuleHandle<NativeArch>) -> SymbolEntry<'_, NativeElfLayout> {
        let mut lookup = SymbolLookup::new("value");
        let symbol = module
            .exports()
            .lookup(&mut lookup)
            .expect("test module must contain a symbol");
        SymbolEntry::new(symbol, SymbolInfo::from_str("value", None))
    }

    fn scope(modules: impl IntoIterator<Item = SyntheticModule<NativeArch>>) -> LookupScope {
        let mut scope = ModuleScope::new(DomainId::PROCESS);
        scope.extend(modules);
        LookupScope::from_group(scope)
    }

    #[test]
    fn symbol_visibility_controls_scope_lookup() {
        let source = ModuleHandle::new(SyntheticModule::new(
            "source",
            [SyntheticSymbol::function("value", 0x100usize as *const ())
                .with_other(ElfSymbolVisibility::PROTECTED.raw())],
        ));
        let external = SyntheticModule::new(
            "external",
            [SyntheticSymbol::function("value", 0x200usize as *const ())],
        );
        let external_scope = scope([external]);
        let resolver = SymbolResolver::new(&source, external_scope, None, None, false);
        let def = resolver
            .find(&symbol(&source))
            .expect("protected definition must resolve locally");
        assert_eq!(def.resolve().unwrap(), VmAddr::new(0x100));

        let source = ModuleHandle::new(SyntheticModule::new(
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
        ));
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
        let resolver = SymbolResolver::new(&source, scope.clone(), None, None, false);
        let def = resolver
            .find(&symbol(&source))
            .expect("lookup must continue past a hidden definition");
        assert_eq!(def.resolve().unwrap(), VmAddr::new(0x300));

        let hidden_ref = ModuleHandle::new(SyntheticModule::new(
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
        ));
        assert!(
            SymbolResolver::new(&hidden_ref, scope, None, None, false)
                .find(&symbol(&hidden_ref))
                .is_none(),
            "hidden undefined reference must not resolve outside its module"
        );
    }

    #[test]
    fn gnu_unique_is_canonical_within_one_registry() {
        let source = ModuleHandle::new(SyntheticModule::new(
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
        ));
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
            None,
            Some(&registry),
            false,
        );
        let definition = first.find(&symbol(&source)).unwrap();
        assert_eq!(definition.resolve().unwrap(), VmAddr::new(0x100));
        assert!(definition.definition().unwrap().1.state().is_nodelete());

        let second = SymbolResolver::new(
            &source,
            scope([unique("second", 0x200)]),
            None,
            Some(&registry),
            false,
        );
        assert_eq!(
            second.find(&symbol(&source)).unwrap().resolve().unwrap(),
            VmAddr::new(0x100)
        );

        let other_registry = SymbolRegistry::new();
        let other = SymbolResolver::new(
            &source,
            scope([unique("other", 0x300)]),
            None,
            Some(&other_registry),
            false,
        );
        assert_eq!(
            other.find(&symbol(&source)).unwrap().resolve().unwrap(),
            VmAddr::new(0x300)
        );
    }
}
