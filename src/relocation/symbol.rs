use super::LookupOrder;
use super::traits::RelocationArch;
use crate::{
    Result,
    elf::{ElfSymbol, ElfSymbolBind, SymbolEntry},
    hint::unlikely,
    image::{
        ExportTable, LocalScope, Module, ModuleHandle, ModuleInstanceId, ModuleScope, SymbolLookup,
    },
    logging,
    memory::VmAddr,
    sync::{Arc, Weak},
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use spin::Mutex;

struct UniqueDef<Arch: RelocationArch> {
    symbol: Arc<ElfSymbol<Arch::Layout>>,
    source: Weak<dyn Module<Arch>>,
}

/// GNU unique symbol state shared by one linker context.
pub(crate) struct SymbolRegistry<Arch: RelocationArch> {
    unique: Mutex<BTreeMap<Box<[u8]>, UniqueDef<Arch>>>,
    pending_pins: Mutex<Vec<ModuleInstanceId>>,
}

impl<Arch: RelocationArch> SymbolRegistry<Arch> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            unique: Mutex::new(BTreeMap::new()),
            pending_pins: Mutex::new(Vec::new()),
        }
    }

    #[inline]
    pub(crate) fn queue_pin(&self, provider: ModuleInstanceId) {
        let mut pins = self.pending_pins.lock();
        if !pins.contains(&provider) {
            pins.push(provider);
        }
    }

    #[inline]
    pub(crate) fn take_pending_pins(&self) -> Vec<ModuleInstanceId> {
        core::mem::take(&mut *self.pending_pins.lock())
    }

    fn resolve_unique<'lib>(
        &self,
        name: &[u8],
        symbol: &ElfSymbol<Arch::Layout>,
        source: &ModuleHandle<Arch>,
    ) -> SymDef<'lib, Arch> {
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
        SymDef::Unique { symbol, source }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct BindingEffect {
    pub(crate) provider: Option<ModuleInstanceId>,
    pin: Option<ModuleInstanceId>,
}

impl BindingEffect {
    #[inline]
    pub(crate) const fn pin(self) -> Option<ModuleInstanceId> {
        self.pin
    }
}

/// A symbol definition found during relocation.
///
/// Local definitions are relative to the resolver's requesting module.
/// Supply that same module when using the definition.
pub enum SymDef<'lib, Arch: RelocationArch> {
    /// An ordinary definition from the exact requesting module.
    Local {
        symbol: &'lib ElfSymbol<Arch::Layout>,
    },
    Defined {
        symbol: &'lib ElfSymbol<Arch::Layout>,
        source: &'lib dyn Module<Arch>,
    },
    Unique {
        symbol: Arc<ElfSymbol<Arch::Layout>>,
        source: ModuleHandle<Arch>,
    },
    WeakUndef,
}

impl<'lib, Arch: RelocationArch> SymDef<'lib, Arch> {
    #[inline]
    pub(crate) fn defined(
        symbol: &'lib ElfSymbol<Arch::Layout>,
        source: &'lib dyn Module<Arch>,
    ) -> Self {
        Self::Defined { symbol, source }
    }

    #[inline]
    pub(crate) fn definition<'a>(
        &'a self,
        local: &'a dyn Module<Arch>,
    ) -> Option<(&'a ElfSymbol<Arch::Layout>, &'a dyn Module<Arch>)> {
        match self {
            Self::Local { symbol } => Some((symbol, local)),
            Self::Defined { symbol, source } => Some((symbol, *source)),
            Self::Unique { symbol, source } => Some((symbol, source.as_ref())),
            Self::WeakUndef => None,
        }
    }

    #[inline]
    pub(crate) fn effect<M: Module<Arch> + ?Sized>(&self, local: &M) -> BindingEffect {
        let state = match self {
            Self::Local { .. } => local.state(),
            Self::Defined { source, .. } => source.state(),
            Self::Unique { source, .. } => source.state(),
            Self::WeakUndef => return BindingEffect::default(),
        };
        let provider = Some(state.instance_id());
        BindingEffect {
            provider,
            pin: if matches!(self, Self::Unique { .. }) {
                provider
            } else {
                None
            },
        }
    }

    #[inline]
    pub(crate) const fn is_weak_undef(&self) -> bool {
        matches!(self, Self::WeakUndef)
    }

    #[inline]
    pub(crate) fn resolve<M: Module<Arch> + ?Sized>(&self, local: &M) -> Result<VmAddr> {
        match self {
            Self::Local { symbol } => local.resolve_symbol(symbol),
            Self::Defined { symbol, source } => source.resolve_symbol(symbol),
            Self::Unique { symbol, source } => source.resolve_symbol(symbol),
            Self::WeakUndef => Ok(VmAddr::null()),
        }
    }
}

/// Resolves symbols through a fixed, ordered set of borrowed module exports.
pub(crate) struct SymbolResolver<'lib, Arch: RelocationArch> {
    source: &'lib ModuleHandle<Arch>,
    scope: &'lib LocalScope<Arch>,
    modules: Vec<LookupModule<'lib, Arch>>,
    registry: Option<&'lib SymbolRegistry<Arch>>,
    symbolic: bool,
}

struct LookupModule<'scope, Arch: RelocationArch> {
    source: &'scope ModuleHandle<Arch>,
    exports: &'scope ExportTable<Arch::Layout>,
    is_source: bool,
}

impl<'lib, Arch> SymbolResolver<'lib, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(
        source: &'lib ModuleHandle<Arch>,
        scope: &'lib LocalScope<Arch>,
        global: Option<&'lib ModuleScope<Arch>>,
        registry: Option<&'lib SymbolRegistry<Arch>>,
        symbolic: bool,
        order: LookupOrder,
    ) -> Self {
        let (before, after) = match order {
            LookupOrder::GlobalFirst => (global, None),
            LookupOrder::LocalFirst => (None, global),
        };
        let mut modules = Vec::with_capacity(scope.len() + global.map_or(0, |scope| scope.len()));
        modules.extend(
            before
                .into_iter()
                .chain(scope.groups())
                .chain(after)
                .flat_map(|group| group.iter())
                .map(|module| LookupModule {
                    source: module,
                    exports: module.exports(),
                    // Match both allocation and vtable: wrappers sharing state
                    // may still override symbol resolution.
                    is_source: core::ptr::eq(module.as_ref(), source.as_ref()),
                }),
        );
        Self {
            source,
            scope,
            modules,
            registry,
            symbolic,
        }
    }

    #[inline]
    pub(crate) const fn scope(&self) -> &LocalScope<Arch> {
        self.scope
    }

    fn lookup_in_scope<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
        mut accept: impl FnMut(&ModuleHandle<Arch>) -> bool,
    ) -> Option<(
        &'find ElfSymbol<Arch::Layout>,
        &'find LookupModule<'lib, Arch>,
    )> {
        let mut lookup = SymbolLookup::from_info(entry.info().clone());
        for module in &self.modules {
            if !accept(module.source) {
                continue;
            }
            // Definition hints apply only to the exact requesting module.
            lookup.set_symbol_hint(
                module
                    .is_source
                    .then_some(entry.symbol() as *const ElfSymbol<Arch::Layout> as usize),
            );
            if let Some(symbol) = module
                .exports
                .lookup(&mut lookup)
                .filter(|symbol| symbol.is_exported())
            {
                logging::trace!(
                    "binding file [{}] to [{}]: symbol [{}]",
                    self.source.name().escape_ascii(),
                    module.source.name().escape_ascii(),
                    entry.name().escape_ascii()
                );
                return Some((symbol, module));
            }
        }
        None
    }

    fn bind<'find>(
        &self,
        name: &[u8],
        symbol: &'find ElfSymbol<Arch::Layout>,
        source: &'find ModuleHandle<Arch>,
        is_source: bool,
    ) -> SymDef<'find, Arch> {
        if unlikely(symbol.bind() == ElfSymbolBind::GNU_UNIQUE) {
            self.bind_unique(name, symbol, source)
        } else if is_source {
            SymDef::Local { symbol }
        } else {
            SymDef::defined(symbol, source.as_ref())
        }
    }

    #[cold]
    #[inline(never)]
    fn bind_unique<'find>(
        &self,
        name: &[u8],
        symbol: &'find ElfSymbol<Arch::Layout>,
        source: &'find ModuleHandle<Arch>,
    ) -> SymDef<'find, Arch> {
        if let Some(registry) = &self.registry {
            registry.resolve_unique(name, symbol, source)
        } else {
            SymDef::Unique {
                symbol: Arc::new(symbol.clone()),
                source: source.clone(),
            }
        }
    }

    #[inline(always)]
    pub(crate) fn find<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
    ) -> Option<SymDef<'find, Arch>> {
        let sym = entry.symbol();
        let binds_locally = unlikely(sym.binds_local()) || (self.symbolic && !sym.is_undef());
        if !binds_locally && let Some((symbol, module)) = self.lookup_in_scope(entry, |_| true) {
            return Some(self.bind(entry.name(), symbol, module.source, module.is_source));
        }
        (!sym.is_undef())
            .then(|| self.bind(entry.name(), sym, self.source, true))
            .or_else(|| Self::weak_undef(sym))
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn find_copy<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
    ) -> Option<(SymDef<'find, Arch>, BindingEffect)> {
        let source_id = self.source.source_id();
        let (symbol, module) =
            self.lookup_in_scope(entry, |source| source.source_id() != source_id)?;
        let pin = if symbol.bind() != ElfSymbolBind::GNU_UNIQUE {
            None
        } else if let Some(registry) = &self.registry {
            registry
                .resolve_unique(entry.name(), entry.symbol(), self.source)
                .effect(self.source.as_ref())
                .pin()
        } else {
            Some(self.source.state().instance_id())
        };
        let definition = SymDef::defined(symbol, module.source.as_ref());
        let mut effect = definition.effect(self.source.as_ref());
        effect.pin = pin;
        Some((definition, effect))
    }

    #[cold]
    fn weak_undef<'find>(sym: &'find ElfSymbol<Arch::Layout>) -> Option<SymDef<'find, Arch>> {
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
    use super::{LookupOrder, SymbolRegistry, SymbolResolver};
    use crate::runtime::{AddressSpaceId, Domain};
    use crate::{
        arch::NativeArch,
        elf::{
            ElfSectionIndex, ElfSymbolBind, ElfSymbolType, ElfSymbolVisibility, NativeElfLayout,
            SymbolEntry, SymbolInfo, SymbolLookup,
        },
        image::{LocalScope, ModuleHandle, ModuleScope, SyntheticModule, SyntheticSymbol},
        memory::VmAddr,
    };

    fn symbol(module: &ModuleHandle<NativeArch>) -> SymbolEntry<'_, NativeElfLayout> {
        let mut lookup = SymbolLookup::new("value");
        let symbol = module
            .exports()
            .lookup(&mut lookup)
            .expect("test module must contain a symbol");
        SymbolEntry::new(symbol, SymbolInfo::from_bytes(b"value", None))
    }

    fn scope(modules: impl IntoIterator<Item = SyntheticModule<NativeArch>>) -> LocalScope {
        let mut scope =
            ModuleScope::new(Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id());
        scope.extend(modules).unwrap();
        LocalScope::from_group(scope)
    }

    fn definition(name: &str, value: usize) -> SyntheticModule<NativeArch> {
        SyntheticModule::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            name,
            [SyntheticSymbol::function(c"value", value as *const ())],
        )
    }

    #[test]
    fn lookup_order_selects_scope() {
        let source = ModuleHandle::new(SyntheticModule::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "source",
            [SyntheticSymbol::from_fields(
                c"value",
                0,
                0,
                ElfSymbolBind::GLOBAL,
                ElfSymbolType::NOTYPE,
                ElfSymbolVisibility::DEFAULT.raw(),
                ElfSectionIndex::UNDEF,
                None,
            )],
        ));
        let local = scope([definition("local", 0x100)]);
        let mut global =
            ModuleScope::new(Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id());
        global
            .push(ModuleHandle::new(definition("global", 0x200)))
            .unwrap();

        for (order, expected) in [
            (LookupOrder::GlobalFirst, 0x200),
            (LookupOrder::LocalFirst, 0x100),
        ] {
            let resolver = SymbolResolver::new(&source, &local, Some(&global), None, false, order);
            assert_eq!(
                resolver
                    .find(&symbol(&source))
                    .unwrap()
                    .resolve(source.as_ref())
                    .unwrap(),
                VmAddr::new(expected)
            );
        }
    }

    #[test]
    fn symbol_visibility_controls_scope_lookup() {
        let source = ModuleHandle::new(SyntheticModule::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "source",
            [SyntheticSymbol::function(c"value", 0x100usize as *const ())
                .with_other(ElfSymbolVisibility::PROTECTED.raw())],
        ));
        let external = SyntheticModule::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "external",
            [SyntheticSymbol::function(c"value", 0x200usize as *const ())],
        );
        let external_scope = scope([external]);
        let resolver = SymbolResolver::new(
            &source,
            &external_scope,
            None,
            None,
            false,
            LookupOrder::GlobalFirst,
        );
        let def = resolver
            .find(&symbol(&source))
            .expect("protected definition must resolve locally");
        assert_eq!(def.resolve(source.as_ref()).unwrap(), VmAddr::new(0x100));

        let source = ModuleHandle::new(SyntheticModule::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "source",
            [SyntheticSymbol::from_fields(
                c"value",
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
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "hidden",
            [SyntheticSymbol::function(c"value", 0x200usize as *const ())
                .with_other(ElfSymbolVisibility::HIDDEN.raw())],
        );
        let visible = SyntheticModule::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "visible",
            [SyntheticSymbol::function(c"value", 0x300usize as *const ())],
        );
        let scope = scope([hidden, visible]);
        let resolver =
            SymbolResolver::new(&source, &scope, None, None, false, LookupOrder::GlobalFirst);
        let def = resolver
            .find(&symbol(&source))
            .expect("lookup must continue past a hidden definition");
        assert_eq!(def.resolve(source.as_ref()).unwrap(), VmAddr::new(0x300));

        let hidden_ref = ModuleHandle::new(SyntheticModule::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "source",
            [SyntheticSymbol::from_fields(
                c"value",
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
            SymbolResolver::new(
                &hidden_ref,
                &scope,
                None,
                None,
                false,
                LookupOrder::GlobalFirst,
            )
            .find(&symbol(&hidden_ref))
            .is_none(),
            "hidden undefined reference must not resolve outside its module"
        );
    }

    #[test]
    fn gnu_unique_is_canonical_within_one_registry() {
        let source = ModuleHandle::new(SyntheticModule::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "source",
            [SyntheticSymbol::from_fields(
                c"value",
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
                &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
                name,
                [SyntheticSymbol::from_fields(
                    c"value",
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
        let first_scope = scope([unique("first", 0x100)]);
        let first = SymbolResolver::new(
            &source,
            &first_scope,
            None,
            Some(&registry),
            false,
            LookupOrder::GlobalFirst,
        );
        let definition = first.find(&symbol(&source)).unwrap();
        assert_eq!(
            definition.resolve(source.as_ref()).unwrap(),
            VmAddr::new(0x100)
        );
        assert_eq!(
            definition.effect(source.as_ref()).pin(),
            Some(
                definition
                    .definition(source.as_ref())
                    .unwrap()
                    .1
                    .state()
                    .instance_id()
            )
        );

        let second_scope = scope([unique("second", 0x200)]);
        let second = SymbolResolver::new(
            &source,
            &second_scope,
            None,
            Some(&registry),
            false,
            LookupOrder::GlobalFirst,
        );
        assert_eq!(
            second
                .find(&symbol(&source))
                .unwrap()
                .resolve(source.as_ref())
                .unwrap(),
            VmAddr::new(0x100)
        );

        let other_registry = SymbolRegistry::new();
        let other_scope = scope([unique("other", 0x300)]);
        let other = SymbolResolver::new(
            &source,
            &other_scope,
            None,
            Some(&other_registry),
            false,
            LookupOrder::GlobalFirst,
        );
        assert_eq!(
            other
                .find(&symbol(&source))
                .unwrap()
                .resolve(source.as_ref())
                .unwrap(),
            VmAddr::new(0x300)
        );
    }
}
