use crate::{
    LinkerError, RelocReason, Result,
    elf::{
        ElfLayout, ElfRelEntry, ElfRelType, ElfSectionId, ElfSectionIndex, ElfSectionType, ElfShdr,
        ElfSymbol, ElfSymbolType, ElfWord,
    },
    image::{LoadedCore, LoadedObject, ModuleScope, RawObject, exports_handle},
    logging,
    memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
    object::{ObjectExports, ObjectSegmentView, section_entries},
    observer::{
        Finalizer, InitEvent, ObjectRelocatedEvent, RelocationObserver, SymbolBindingEvent,
    },
    relocate_context_error,
    relocation::{
        ObjectRelocationArch, RelocHelper, RelocateArgs, RelocationHandler, resolve_symbol_addr,
    },
    runtime::CodeExecutor,
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
    Arch: ObjectRelocationArch,
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

#[inline]
pub(crate) fn object_relocation_addend<Arch, Memory>(
    memory: &Memory,
    target: &ElfShdr<Arch::Layout>,
    rel: &ElfRelType<Arch>,
) -> Result<isize>
where
    Arch: ObjectRelocationArch,
    Memory: ImageMemory,
{
    if !<ElfRelType<Arch> as ElfRelEntry<Arch::Layout>>::HAS_IMPLICIT_ADDEND {
        return Ok(rel.r_addend(VmAddr::null()));
    }

    let place = VmAddr::new(target.sh_addr()) + rel.r_offset();
    let word = unsafe { memory.read_value::<<Arch::Layout as ElfLayout>::Word>(place)? };
    Ok(word.to_usize() as isize)
}

impl<D: 'static, Arch, R> RawObject<D, Arch, R>
where
    Arch: ObjectRelocationArch,
    R: RegionAccess,
{
    pub(crate) fn relocate_impl<PreH, PostH, Obs>(
        mut self,
        args: RelocateArgs<'_, Arch, PreH, PostH, Obs>,
    ) -> Result<LoadedObject<D, Arch, R>>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        logging::debug!("Relocating object: {}", self.core.name());
        let RelocateArgs {
            scope,
            executor,
            pre_handler,
            post_handler,
            observer,
            ..
        } = args;

        self.simplify_symbols(&scope, observer)?;

        let relocation_segments =
            ObjectSegmentView::new(self.core.segments(), self.init_segments.as_ref());
        let mut helper = RelocHelper::new(
            &self.core,
            self.symtab.view(),
            relocation_segments,
            scope,
            pre_handler,
            post_handler,
            observer,
            executor.as_ref(),
            self.core.tls_get_addr(),
        );
        let shdrs = self.sections.headers();
        let mut state = Arch::ObjectRelocationState::default();
        Arch::prepare_object_relocation(&mut state, &mut helper, shdrs)?;
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
                match Arch::relocate_object(&mut state, &mut helper, rel, target, &mut self.pltgot)
                {
                    Ok(()) => continue,
                    Err(err) => {
                        if helper.handle_post(rel)?.is_unhandled() {
                            return Err(err);
                        }
                    }
                }
            }
        }

        let RelocHelper {
            scope,
            tls_desc_args,
            ..
        } = helper;
        self.core.set_tls_desc_args(tls_desc_args);

        let finalizer = Finalizer::new(core::mem::take(&mut self.fini), executor.clone());
        let event_segments =
            ObjectSegmentView::new(self.core.segments(), self.init_segments.as_ref());
        let mut event = ObjectRelocatedEvent::new(
            &self.core,
            &self.sections,
            self.symtab.view(),
            event_segments,
            finalizer,
        );
        observer.on_object_relocated(&mut event)?;
        let (exports, finalizer) = event.into_parts();
        let exports = exports.unwrap_or_else(|| exports_handle(self.default_exports()));
        let inner = crate::sync::Arc::get_mut(&mut self.core.inner).ok_or_else(|| {
            LinkerError::context(
                "raw object core was retained before runtime exports were installed",
            )
        })?;
        inner.exports = exports;
        self.core.set_finalizer(finalizer);

        let object_segments =
            ObjectSegmentView::new(self.core.segments(), self.init_segments.as_ref());
        self.section_segments.mprotect(&object_segments)?;

        self.call_init(observer, object_segments, executor.as_ref())?;
        self.section_segments.mprotect_final(&object_segments)?;

        logging::info!("Relocation completed for {}", self.core.name());

        let core = self.core;
        Ok(LoadedObject {
            inner: LoadedCore::from_relocated_core_scope(core, scope),
        })
    }

    #[inline]
    fn call_init<Obs>(
        &self,
        observer: &mut Obs,
        segments: ObjectSegmentView<'_, R>,
        executor: &dyn CodeExecutor<Arch>,
    ) -> Result<()>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        logging::trace!("[{}] Executing init functions", self.core.name());
        let mut event = InitEvent::new(&self.core, &self.init);
        observer.on_init(&mut event)?;
        event.run_with(&segments, executor)?;
        self.core.set_init();
        Ok(())
    }

    fn simplify_symbols<Obs>(&mut self, scope: &ModuleScope<Arch>, observer: &mut Obs) -> Result<()>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        let base = self.core.base();
        let tls_get_addr = self.core.tls_get_addr();
        let symbol_count = self.symtab.symbols().len();

        for idx in 0..symbol_count {
            let value = {
                let (symbol, syminfo) = self.symtab.symbol_idx(idx);
                if symbol.symbol_type() == ElfSymbolType::FILE {
                    continue;
                }

                let addr = if symbol.is_undef() {
                    let resolved =
                        resolve_symbol_addr(&self.core, scope, symbol, &syminfo, tls_get_addr);
                    let mut event =
                        SymbolBindingEvent::new(&self.core, None, symbol, syminfo.name(), resolved);
                    observer.on_symbol_binding(&mut event)?;
                    let Some(resolved) = event.into_resolved_addr() else {
                        return Err(unresolved_symbol_error(&self.core, syminfo.name()));
                    };
                    resolved
                } else if symbol.st_shndx().is_abs() {
                    VmAddr::new(symbol.st_value())
                } else {
                    let Some(section_id) = ElfSectionId::from_symbol_shndx(symbol.st_shndx())
                    else {
                        continue;
                    };
                    VmAddr::new(self.sections.section(section_id).sh_addr())
                        .wrapping_add(VmOffset::new(symbol.st_value()))
                };
                addr.wrapping_offset_from(base).get()
            };

            let symbols = self.symtab.symbols_mut();
            symbols[idx].set_value(value);
        }

        Ok(())
    }

    fn default_exports(&self) -> ObjectExports<Arch::Layout> {
        let mut exports = ObjectExports::empty();
        for idx in 0..self.symtab.symbols().len() {
            let (symbol, info) = self.symtab.symbol_idx(idx);
            if symbol.is_undef()
                || !symbol.is_ok_bind()
                || !symbol.is_ok_type()
                || self.symbol_uses_init_memory(symbol)
            {
                continue;
            }
            exports.insert(info.name(), symbol.clone());
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
fn unresolved_symbol_error<D, Arch, R>(
    core: &crate::image::ElfCore<D, Arch, R>,
    name: &str,
) -> crate::Error
where
    D: 'static,
    Arch: crate::relocation::RelocationArch,
    R: RegionAccess,
{
    relocate_context_error(
        core.name(),
        "object symbol",
        Some(name),
        RelocReason::UnknownSymbol,
    )
}
