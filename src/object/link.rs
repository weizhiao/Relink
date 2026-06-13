use crate::{
    RelocReason, Result,
    elf::{
        ElfLayout, ElfRelEntry, ElfRelType, ElfSectionId, ElfSectionIndex, ElfSectionType, ElfShdr,
        ElfSymbol, ElfSymbolType, ElfWord,
    },
    image::{ModuleScope, RawObject},
    logging,
    memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
    object::{ObjectExports, ObjectSegmentView, section_entries},
    observer::{InitEvent, RelocationObserver, SymbolBindingEvent},
    relocate_context_error,
    relocation::{
        ObjectRelocationArch, RelocHelper, RelocateArgs, RelocationHandler, resolve_symbol_addr,
    },
    runtime::CodeExecutor,
    sync::Arc,
};

pub(crate) fn object_relocation_sections<Arch>(
    shdrs: &[ElfShdr<Arch::Layout>],
) -> impl Iterator<Item = (&ElfShdr<Arch::Layout>, &ElfShdr<Arch::Layout>)> + '_
where
    Arch: ObjectRelocationArch,
{
    shdrs
        .iter()
        .filter(|shdr| {
            matches!(
                shdr.section_type(),
                ElfSectionType::REL | ElfSectionType::RELA
            )
        })
        .map(move |relocation_shdr| {
            let target = &shdrs[relocation_shdr.sh_info() as usize];
            (target, relocation_shdr)
        })
}

pub(crate) fn object_relocation_entries<Arch, Memory>(
    memory: &Memory,
    shdr: &ElfShdr<Arch::Layout>,
) -> Result<&'static [ElfRelType<Arch>]>
where
    Arch: ObjectRelocationArch,
    Memory: ImageMemory + ?Sized,
{
    section_entries(memory, shdr)
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
    ) -> Result<crate::image::LoadedCore<D, Arch, R>>
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
        let shdrs = &self.shdrs;
        let mut state = Arch::ObjectRelocationState::default();
        Arch::prepare_object_relocation(&mut state, &mut helper, shdrs)?;
        for (target, relocation_shdr) in object_relocation_sections::<Arch>(shdrs) {
            let rels = object_relocation_entries::<Arch, _>(helper.memory(), relocation_shdr)?;
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

        let exports = self.build_exports();
        self.install_exports(exports);

        let object_segments =
            ObjectSegmentView::new(self.core.segments(), self.init_segments.as_ref());
        (self.mprotect)(&object_segments)?;

        self.call_init(observer, object_segments, executor.as_ref())?;
        self.finish_init_metadata();
        drop(self.init_segments.take());
        self.core.set_init();

        logging::info!("Relocation completed for {}", self.core.name());

        Ok(crate::image::LoadedCore::from_relocated_core_deps(
            self.core, scope,
        ))
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
                    VmAddr::new(self.shdrs[section_id.index()].sh_addr())
                        .wrapping_add(VmOffset::new(symbol.st_value()))
                };
                offset_from_base(addr, base)
            };

            let symbols = self.symtab.symbols_mut();
            symbols[idx].set_value(value);
        }

        Ok(())
    }

    fn finish_init_metadata(&mut self) {
        if !self.discard_symtab_after_init {
            return;
        }

        self.symtab = crate::object::ObjectSymbolTable::empty_object();
    }

    fn install_exports(&mut self, exports: ObjectExports<Arch::Layout>) {
        let inner = Arc::get_mut(&mut self.core.inner)
            .expect("raw object core must be uniquely owned before runtime exports are installed");
        inner.exports = crate::image::exports_handle(exports);
    }

    fn build_exports(&self) -> ObjectExports<Arch::Layout> {
        ObjectExports::from_symtab(self.symtab.view(), |symbol| {
            !self.symbol_uses_init_memory(symbol)
        })
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
        let section_addr = VmAddr::new(self.shdrs[section_id.index()].sh_addr());
        init_segments.contains_addr(section_addr)
    }
}

#[inline]
fn offset_from_base(addr: VmAddr, base: VmAddr) -> usize {
    addr.wrapping_offset_from(base).get()
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
