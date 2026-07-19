use super::traits::RelocationArch;
use crate::{
    Result,
    elf::{ElfSymbol, ElfSymbolType, SymbolEntry},
    hint::unlikely,
    image::{Module, ModuleScope, SymbolLookup},
    logging,
    memory::{VmAddr, VmOffset},
    runtime::{CodeContext, CodeExecutor},
    tls::TlsResolver,
};

/// A symbol definition found during relocation.
///
/// Contains the symbol information and the module where it was found.
/// Used to compute the final address of a symbol.
pub enum SymDef<'lib, Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    Defined {
        symbol: &'lib ElfSymbol<Arch::Layout>,
        source: &'lib dyn Module<Arch, Tls>,
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
    fn weak_undef() -> Self {
        Self::WeakUndef
    }

    /// Computes the symbol address (base + st_value).
    ///
    /// For regular symbols, returns base + st_value. For absolute symbols,
    /// returns st_value unchanged.
    /// For IFUNC symbols, returns the resolver address without executing it.
    /// For undefined weak symbols, returns null.
    pub(crate) fn addr(&self) -> VmAddr {
        match self {
            Self::Defined { symbol, source } => {
                if symbol.st_shndx().is_abs() {
                    VmAddr::new(symbol.st_value())
                } else {
                    source.memory().base() + VmOffset::new(symbol.st_value())
                }
            }
            Self::WeakUndef => VmAddr::null(),
        }
    }

    #[inline]
    pub(crate) fn resolve_addr(&self, executor: &dyn CodeExecutor<Arch>) -> Result<VmAddr> {
        let addr = self.addr();
        if unlikely(matches!(
            self,
            Self::Defined { symbol, .. } if symbol.symbol_type() == ElfSymbolType::GNU_IFUNC
        )) {
            self.resolve_ifunc_addr(executor, addr)
        } else {
            Ok(addr)
        }
    }

    #[cold]
    #[inline(never)]
    fn resolve_ifunc_addr(
        &self,
        executor: &dyn CodeExecutor<Arch>,
        resolver: VmAddr,
    ) -> Result<VmAddr> {
        let Self::Defined { source, .. } = self else {
            unreachable!("undefined weak symbols cannot be IFUNC resolvers")
        };
        executor.resolve_ifunc(
            CodeContext::<Arch>::new(source.name(), source.memory()),
            resolver,
        )
    }
}

pub(crate) struct SymbolResolver<'lib, Source, Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    source: &'lib Source,
    scope: ModuleScope<Arch, Tls>,
    symbolic: bool,
}

impl<'lib, Source, Arch, Tls> SymbolResolver<'lib, Source, Arch, Tls>
where
    Source: Module<Arch, Tls>,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    pub(crate) const fn new(
        source: &'lib Source,
        scope: ModuleScope<Arch, Tls>,
        symbolic: bool,
    ) -> Self {
        Self {
            source,
            scope,
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

    pub(crate) fn find<'find>(
        &'find self,
        entry: &SymbolEntry<'find, Arch::Layout>,
    ) -> Option<SymDef<'find, Arch, Tls>> {
        let sym = entry.symbol();
        let self_def = || (!sym.is_undef()).then(|| SymDef::defined(sym, self.source));
        if unlikely(sym.binds_local()) {
            return self_def().or_else(|| Self::weak_undef(sym));
        }

        let scope_def = || {
            let mut lookup = SymbolLookup::from_info(entry.info().clone());
            self.scope.iter().find_map(|scope_source| {
                scope_source
                    .exports()
                    .lookup(&mut lookup)
                    .filter(|sym| sym.is_exported())
                    .map(|sym| {
                        logging::trace!(
                            "binding file [{}] to [{}]: symbol [{}]",
                            self.source.name(),
                            scope_source.name(),
                            entry.name()
                        );
                        SymDef::defined(sym, &**scope_source)
                    })
            })
        };

        if self.symbolic {
            self_def().or_else(scope_def)
        } else {
            scope_def().or_else(self_def)
        }
        .or_else(|| Self::weak_undef(sym))
    }

    #[cold]
    fn weak_undef<'find>(sym: &'find ElfSymbol<Arch::Layout>) -> Option<SymDef<'find, Arch, Tls>> {
        if sym.is_weak() && sym.is_undef() {
            debug_assert_eq!(sym.st_value(), 0);
            Some(SymDef::weak_undef())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SymbolResolver;
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
        let resolver = SymbolResolver::new(&source, external_scope, false);
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
        let resolver = SymbolResolver::new(&source, scope.clone(), false);
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
            SymbolResolver::new(&hidden_ref, scope, false)
                .find(&symbol(&hidden_ref))
                .is_none(),
            "hidden undefined reference must not resolve outside its module"
        );
    }
}
