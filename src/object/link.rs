use crate::{
    Error, RelocReason, Result,
    elf::{
        ElfLayout, ElfRelType, ElfSectionId, ElfSectionIndex, ElfSectionType, ElfShdr, ElfSymbol,
        ElfSymbolType,
    },
    image::{
        ElfCore, GlobalScope, LoadedCore, LoadedObject, RawObject, SymbolLookup, SymbolMap,
        SymbolName, SyntheticSymbol,
    },
    lazy::LazyBinder,
    logging,
    memory::{RegionAccess, VmAddr, VmOffset},
    object::{ObjectSections, ObjectSegmentView, ObjectSymbolTable, section_entries},
    observer::{LifecycleRunner, ObjectRelocatedEvent, RelocationObserver, SymbolBindingEvent},
    relocate_context_error,
    relocation::{
        BindingDeps, ObjectArch, RelocHelper, RelocateArgs, RelocationArch, SymbolResolver,
    },
    runtime::CodeContext,
    tls::TlsResolver,
};

pub(crate) fn object_relocation_sections<Arch>(
    shdrs: &[ElfShdr<Arch::Layout>],
) -> impl Iterator<
    Item = (
        ElfSectionId,
        ElfSectionId,
        &ElfShdr<Arch::Layout>,
        &ElfShdr<Arch::Layout>,
    ),
> + '_
where
    Arch: ObjectArch,
{
    shdrs
        .iter()
        .enumerate()
        .filter(|shdr| {
            matches!(
                shdr.1.section_type(),
                ElfSectionType::REL | ElfSectionType::RELA
            )
        })
        .map(move |(relocation_index, relocation_shdr)| {
            let target_id = ElfSectionId::new(relocation_shdr.sh_info() as usize);
            let relocation_id = ElfSectionId::new(relocation_index);
            let target = &shdrs[target_id.index()];
            (target_id, relocation_id, target, relocation_shdr)
        })
}

impl<D: Send + Sync + 'static, Arch, R, Tls> RawObject<D, Arch, R, Tls>
where
    Arch: ObjectArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn relocate_impl<Obs, Binder>(
        mut self,
        args: RelocateArgs<'_, Arch, Obs, Binder>,
    ) -> Result<LoadedObject<D, Arch, R, Tls>>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
        Binder: LazyBinder<Arch> + ?Sized,
    {
        logging::debug!("Relocating object: {}", self.core.name().escape_ascii());
        let RelocateArgs {
            scope,
            global,
            symbols,
            lookup_order,
            run_init,
            observer,
            ..
        } = args;
        // Stabilize global lookup order and retain providers until dependency
        // bindings have been installed on the relocated module.
        let global_snapshot = global.as_ref().map(GlobalScope::modules);
        let source = self.core.module_handle();
        let resolver = SymbolResolver::new(
            &source,
            &scope,
            global_snapshot.as_ref(),
            symbols.as_deref(),
            self.core.symbolic(),
            lookup_order,
        );
        let mut bindings = BindingDeps::new();
        Self::simplify_symbols(
            &self.core,
            &self.sections,
            &mut self.symtab,
            &resolver,
            &mut bindings,
            observer,
        )?;

        let relocation_segments =
            ObjectSegmentView::new(self.core.segments(), self.init_segments.as_ref());
        let mut helper = RelocHelper::new(
            &self.core,
            &resolver,
            bindings,
            self.symtab.view(),
            relocation_segments,
            observer,
        );
        let shdrs = self.sections.headers();
        let mut state = Arch::State::default();
        Arch::prepare_relocation(&mut state, &mut helper, shdrs)?;
        for (target_id, relocation_id, target, relocation_shdr) in
            object_relocation_sections::<Arch>(shdrs)
        {
            if !self.section_is_mapped(target_id) || !self.section_is_mapped(relocation_id) {
                continue;
            }
            let rels = section_entries::<Arch::Layout, ElfRelType<Arch>, _>(
                helper.memory(),
                relocation_shdr,
            )?;
            for rel in rels {
                if !helper.handle_pre(rel)?.is_unhandled() {
                    continue;
                }
                match Arch::relocate(&mut state, &mut helper, rel, target, &mut self.pltgot) {
                    Ok(()) => continue,
                    Err(err) => {
                        if helper.handle_post(rel)?.is_unhandled() {
                            return Err(err);
                        }
                    }
                }
            }
        }

        let bindings = helper.into_bindings();
        drop(resolver);

        let initializer = LifecycleRunner::new(core::mem::take(&mut self.init));
        let finalizer = LifecycleRunner::new(core::mem::take(&mut self.fini));
        let event_segments =
            ObjectSegmentView::new(self.core.segments(), self.init_segments.as_ref());
        let mut event = ObjectRelocatedEvent::new(
            &self.core,
            &self.sections,
            &self.symtab,
            event_segments,
            initializer,
            finalizer,
        );
        observer.on_object_relocated(&mut event)?;
        let (exports, mut lifecycle) = event.into_parts();
        let exports = exports.unwrap_or_else(|| self.default_exports());
        self.core.inner.exports.install_object(exports);
        let object_segments =
            ObjectSegmentView::new(self.core.segments(), self.init_segments.as_ref());
        self.section_segments.mprotect(&object_segments)?;

        let RawObject {
            core,
            section_segments,
            init_segments,
            ..
        } = self;
        let core_ref = core.downgrade();
        lifecycle.initializer_mut().append_hook(move |event| {
            let core = core_ref
                .upgrade()
                .expect("object core must remain alive during initialization");
            let memory = ObjectSegmentView::new(core.segments(), init_segments.as_ref());
            let ctx = CodeContext::<Arch>::new(core.name(), &memory);
            for addr in event.lifecycle().func_addrs() {
                core.executor().call_lifecycle(ctx, addr)?;
            }
            section_segments.mprotect_final(&memory)?;
            event.lifecycle_mut().clear();
            Ok(())
        });
        core.set_lifecycle(lifecycle);

        if run_init {
            logging::trace!("[{}] Executing init functions", core.name().escape_ascii());
            core.initialize()?;
        }

        logging::info!("Relocation completed for {}", core.name().escape_ascii());

        bindings.install(core.state());
        let inner = unsafe {
            LoadedCore::from_relocated(core, scope, global.as_ref(), symbols, lookup_order)
        };
        Ok(LoadedObject { inner })
    }

    fn simplify_symbols<Obs>(
        core: &ElfCore<D, Arch, R, Tls>,
        sections: &ObjectSections<Arch::Layout>,
        symtab: &mut ObjectSymbolTable<Arch::Layout>,
        resolver: &SymbolResolver<'_, Arch>,
        bindings: &mut BindingDeps,
        observer: &mut Obs,
    ) -> Result<()>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        let base = core.segments().base();
        let symbol_count = symtab.symbols().len();

        // The mandatory null symbol stays zero and never participates in lookup.
        for idx in 1..symbol_count {
            let value = {
                let symbol = &symtab.symbols()[idx];
                if symbol.symbol_type() == ElfSymbolType::FILE {
                    continue;
                }

                let addr = if symbol.is_undef() {
                    let entry = symtab.view().entry(idx);
                    let definition = resolver.find(&entry);
                    let effect = definition
                        .as_ref()
                        .map(|definition| definition.effect(&**core))
                        .unwrap_or_default();
                    let resolved = definition
                        .as_ref()
                        .map(|definition| definition.resolve(&**core))
                        .transpose()?;
                    let mut event =
                        SymbolBindingEvent::new(core, None, symbol, entry.name(), resolved);
                    observer.on_symbol_binding(&mut event)?;
                    let Some(resolved) = event.into_resolved_addr() else {
                        return Err(unresolved_symbol_error(core, entry.name()));
                    };
                    bindings.record(effect);
                    resolved
                } else if symbol.st_shndx().is_abs() {
                    VmAddr::new(symbol.st_value())
                } else {
                    let Some(section_id) = ElfSectionId::from_symbol_shndx(symbol.st_shndx())
                    else {
                        continue;
                    };
                    VmAddr::new(sections.section(section_id).sh_addr())
                        .wrapping_add(VmOffset::new(symbol.st_value()))
                };
                addr.wrapping_offset_from(base).get()
            };

            let symbols = symtab.symbols_mut();
            symbols[idx].set_value(value);
        }

        Ok(())
    }

    fn default_exports(&self) -> SymbolMap<Arch::Layout> {
        // Objects have no GNU version table and satisfy requests by name.
        let mut exports = SymbolMap::empty();
        exports.ignore_versions();
        let view = self.symtab.view();
        for (idx, symbol) in self.symtab.symbols().iter().enumerate() {
            if !symbol.is_exported() || self.symbol_uses_init_memory(symbol) {
                continue;
            }
            insert_export(&mut exports, view.entry(idx).name(), symbol);
        }
        exports
    }

    fn symbol_uses_init_memory(&self, symbol: &ElfSymbol<Arch::Layout>) -> bool {
        let Some(init_segments) = self.init_segments.as_ref() else {
            return false;
        };
        if matches!(
            symbol.st_shndx(),
            ElfSectionIndex::ABS | ElfSectionIndex::COMMON
        ) {
            return false;
        }
        let Some(section_id) = ElfSectionId::from_symbol_shndx(symbol.st_shndx()) else {
            return false;
        };
        let section_addr = VmAddr::new(self.sections.section(section_id).sh_addr());
        init_segments.contains_addr(section_addr)
    }
}

/// Keeps the first definition, except that a strong export replaces a weak one.
fn insert_export<L: ElfLayout>(exports: &mut SymbolMap<L>, name: &[u8], symbol: &ElfSymbol<L>) {
    if exports
        .lookup(&mut SymbolLookup::new(name))
        .is_some_and(|previous| !previous.is_weak() || symbol.is_weak())
    {
        return;
    }
    let name = SymbolName::try_from(name).expect("symbol name contains NUL");
    exports.insert(SyntheticSymbol::from_elf(name, symbol, None));
}

#[cold]
fn unresolved_symbol_error<D, Arch, R, Tls>(core: &ElfCore<D, Arch, R, Tls>, name: &[u8]) -> Error
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    relocate_context_error(
        core.name(),
        "object symbol",
        Some(name),
        RelocReason::UnknownSymbol,
    )
}
