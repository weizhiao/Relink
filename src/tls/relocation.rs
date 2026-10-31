use super::{TlsDescRequest, TlsModule};
use crate::{
    ByteRepr, RelocReason, Result,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord},
    memory::{ImageMemory, ImageMemoryExt, RegionAccess, VmAddr, VmOffset},
    observer::RelocationObserver,
    relocation::{BindingEffect, RelocHelper, RelocationArch},
    tls::TlsResolver,
};

pub(crate) enum TlsRelocOutcome {
    Applied,
    Failed(RelocReason),
}

enum TlsSymbol {
    Defined(TlsDef),
    UndefinedWeak,
}

struct TlsDef {
    offset: usize,
    module: TlsModule,
    effect: BindingEffect,
}

impl<'find, D, Arch, R, Tls, Obs, Memory> RelocHelper<'find, D, Arch, R, Tls, Obs, Memory>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    Obs: RelocationObserver<Arch> + ?Sized,
    Memory: ImageMemory,
    <Arch::Layout as ElfLayout>::Word: ByteRepr,
{
    #[inline]
    fn tls_symbol(&self, rel: &ElfRelType<Arch>) -> core::result::Result<TlsSymbol, RelocReason> {
        let symbol = self.symbol_entry(rel);
        let Some(symdef) = self.find_symdef(&symbol) else {
            return Err(RelocReason::UnknownSymbol);
        };
        if symdef.is_weak_undef() {
            Ok(TlsSymbol::UndefinedWeak)
        } else {
            let effect = symdef.effect(&**self.core);
            let (symbol, source) = symdef
                .definition(&**self.core)
                .expect("defined TLS symbol must retain its provider");
            let Some(module) = source.tls() else {
                return Err(RelocReason::MissingTlsModuleId);
            };
            Ok(TlsSymbol::Defined(TlsDef {
                offset: symbol.st_value(),
                module: module.clone(),
                effect,
            }))
        }
    }

    pub(crate) fn handle_tls_reloc(&mut self, rel: &ElfRelType<Arch>) -> Result<TlsRelocOutcome> {
        let r_type = rel.r_type();
        let r_sym = rel.r_symbol();
        let memory = self.memory();
        let base = memory.base();
        let place = base + rel.r_offset();
        let r_addend = rel.read_addend(memory, place)?;

        // Symbol zero refers to the current module. Undefined weak symbols leave
        // ordinary TLS relocations untouched, but require an explicit TLSDESC.
        let symbol = if r_sym == 0 {
            None
        } else {
            match self.tls_symbol(rel) {
                Ok(TlsSymbol::UndefinedWeak) if Arch::TLSDESC != Some(r_type) => {
                    return Ok(TlsRelocOutcome::Applied);
                }
                Ok(symbol) => Some(symbol),
                Err(reason) => return Ok(TlsRelocOutcome::Failed(reason)),
            }
        };
        let (module, symbol_value, effect) = match &symbol {
            Some(TlsSymbol::Defined(symbol)) => {
                (Some(&symbol.module), symbol.offset, symbol.effect)
            }
            None => (self.core.tls(), 0, BindingEffect::default()),
            Some(TlsSymbol::UndefinedWeak) => (None, 0, BindingEffect::default()),
        };

        match r_type {
            value if Arch::DTPOFF == value => {
                let tls_val = VmAddr::new(symbol_value)
                    .wrapping_add_signed(r_addend)
                    .get()
                    .wrapping_sub(Arch::TLS_DTV_OFFSET);
                unsafe {
                    memory.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(tls_val),
                    )?;
                }
            }
            value if Arch::DTPMOD == Some(value) => {
                let Some(module) = module else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsModuleId));
                };
                let mod_id = module.mod_id();
                unsafe {
                    memory.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(mod_id.get()),
                    )?;
                }
            }
            value if Arch::TPOFF == value => {
                let Some(tp_offset) = module.and_then(TlsModule::tp_offset) else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsTpOffset));
                };
                let tls_val =
                    VmAddr::new(tp_offset.get().wrapping_add(symbol_value as isize) as usize)
                        .wrapping_add_signed(r_addend);
                unsafe {
                    memory.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(tls_val.get()),
                    )?;
                }
            }
            value if Arch::TLSDESC == Some(value) => {
                let request = if matches!(symbol, Some(TlsSymbol::UndefinedWeak)) {
                    TlsDescRequest::UndefinedWeak {
                        addend: r_addend as usize,
                    }
                } else {
                    let Some(module) = module else {
                        return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsModuleId));
                    };
                    TlsDescRequest::Defined {
                        module: module.clone(),
                        offset: VmAddr::new(symbol_value)
                            .wrapping_add_signed(r_addend)
                            .get(),
                    }
                };
                let setup = self.core.tls_resolver().bind_tlsdesc(request)?;
                let (desc, state) = setup.into_parts();
                let arg_place = place
                    + VmOffset::new(core::mem::size_of::<<Arch::Layout as ElfLayout>::Word>());
                unsafe {
                    memory.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(desc.resolver().get()),
                    )?;
                    memory.write_value(
                        arg_place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(desc.arg()),
                    )?;
                }
                self.core.retain_tls_descriptor(state);
            }
            _ => unreachable!("handle_tls_reloc called with a non-TLS relocation"),
        }
        self.record_binding(effect);
        Ok(TlsRelocOutcome::Applied)
    }
}
