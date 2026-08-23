use crate::{
    Error, RelocReason, Result,
    elf::{
        ElfRelType, ElfSectionId, ElfSectionIndex, ElfSectionType, ElfShdr, ElfSymbol,
        ElfSymbolType,
    },
    image::{ElfCore, GlobalScope, LoadedCore, LoadedObject, Module, RawObject, SymbolExports},
    lazy::LazyBinder,
    logging,
    memory::{RegionAccess, VmAddr, VmOffset},
    object::{
        ObjectExports, ObjectSections, ObjectSegmentView, ObjectSymbolTable, section_entries,
    },
    observer::{LifecycleRunner, ObjectRelocatedEvent, RelocationObserver, SymbolBindingEvent},
    relocate_context_error,
    relocation::{
        BindingDeps, ObjectArch, RelocHelper, RelocateArgs, RelocationArch, SymDef, SymbolResolver,
    },
    runtime::CodeContext,
    sync::{Arc, arc_unsize},
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
        args: RelocateArgs<'_, Arch, Tls, Obs, Binder>,
    ) -> Result<LoadedObject<D, Arch, R, Tls>>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
        Binder: LazyBinder<Arch> + ?Sized,
    {
        logging::debug!("Relocating object: {}", self.core.name());
        let RelocateArgs {
            scope,
            global,
            symbols,
            lookup_order,
            run_init,
            observer,
            ..
        } = args;
        let domain = self.core.domain_id();
        scope.check_domain(domain)?;
        if let Some(global) = &global {
            domain.ensure(global.domain_id())?;
        }
        let global_snapshot = global.as_ref().map(GlobalScope::modules);
        let source = self.core.module_handle();
        let resolver = SymbolResolver::new(
            &source,
            scope,
            global_snapshot,
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
            resolver,
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

        let (scope, global_snapshot, bindings) = helper.into_parts();

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
        let exports = exports.unwrap_or_else(|| {
            arc_unsize!(
                Arc::new(self.default_exports()) => dyn SymbolExports<Arch::Layout>
            )
        });
        self.exports.set(exports);
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
            logging::trace!("[{}] Executing init functions", core.name());
            core.initialize()?;
        }

        logging::info!("Relocation completed for {}", core.name());

        bindings.install(core.state());
        let inner = unsafe {
            LoadedCore::from_relocated(core, scope, global.as_ref(), symbols, lookup_order)
        };
        drop(global_snapshot);
        Ok(LoadedObject { inner })
    }

    fn simplify_symbols<Obs>(
        core: &ElfCore<D, Arch, R, Tls>,
        sections: &ObjectSections<Arch::Layout>,
        symtab: &mut ObjectSymbolTable<Arch::Layout>,
        resolver: &SymbolResolver<'_, Arch, Tls>,
        bindings: &mut BindingDeps,
        observer: &mut Obs,
    ) -> Result<()>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        let base = core.base();
        let symbol_count = symtab.symbols().len();

        // The mandatory null symbol stays zero and never participates in lookup.
        for idx in 1..symbol_count {
            let value = {
                let entry = symtab.view().entry(idx);
                let symbol = entry.symbol();
                if symbol.symbol_type() == ElfSymbolType::FILE {
                    continue;
                }

                let addr = if symbol.is_undef() {
                    let definition = resolver.find(&entry);
                    let provider = definition.as_ref().and_then(SymDef::provider_id);
                    let resolved = definition.as_ref().map(SymDef::resolve).transpose()?;
                    let mut event =
                        SymbolBindingEvent::new(core, None, symbol, entry.name(), resolved);
                    observer.on_symbol_binding(&mut event)?;
                    let Some(resolved) = event.into_resolved_addr() else {
                        return Err(unresolved_symbol_error(core, entry.name()));
                    };
                    if let Some(provider) = provider {
                        bindings.record(core.state(), provider);
                    }
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

    fn default_exports(&self) -> ObjectExports<Arch::Layout> {
        let mut exports = ObjectExports::empty();
        for idx in 0..self.symtab.symbols().len() {
            let entry = self.symtab.view().entry(idx);
            let symbol = entry.symbol();
            if !symbol.is_exported() || self.symbol_uses_init_memory(symbol) {
                continue;
            }
            exports.insert(entry.name(), symbol.clone());
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

#[cold]
fn unresolved_symbol_error<D, Arch, R, Tls>(core: &ElfCore<D, Arch, R, Tls>, name: &str) -> Error
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
