use super::defs::{ModuleTls, TlsDescRequest};
use crate::{
    ByteRepr, RelocReason, Result,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord},
    image::{Module, ModuleInstanceId},
    memory::{ImageMemory, ImageMemoryExt, RegionAccess, VmAddr, VmOffset},
    observer::RelocationObserver,
    relocation::{RelocHelper, RelocationArch},
    tls::TlsResolver,
};

pub(crate) enum TlsRelocOutcome {
    Applied,
    Failed(RelocReason),
}

struct TlsDef {
    offset: usize,
    module: ModuleTls,
    provider: ModuleInstanceId,
}

impl<'find, D: Send + Sync + 'static, Arch, R, Tls, Obs, H, Memory>
    RelocHelper<'find, D, Arch, R, Tls, Obs, H, Memory>
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
    fn tls_def(&self, rel: &ElfRelType<Arch>) -> core::result::Result<TlsDef, TlsRelocOutcome> {
        let symbol = self.symbol_entry(rel);
        let Some(symdef) = self.find_symdef(&symbol) else {
            return Err(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
        };
        if symdef.is_weak_undef() {
            Err(TlsRelocOutcome::Applied)
        } else {
            let (symbol, source) = symdef
                .definition()
                .expect("defined TLS symbol must retain its provider");
            let Some(module) = source.tls() else {
                return Err(TlsRelocOutcome::Failed(RelocReason::MissingTlsModuleId));
            };
            Ok(TlsDef {
                offset: symbol.st_value(),
                module,
                provider: source.state().instance_id(),
            })
        }
    }

    pub(crate) fn handle_tls_reloc(&mut self, rel: &ElfRelType<Arch>) -> Result<TlsRelocOutcome> {
        let r_type = rel.r_type();
        let r_sym = rel.r_symbol();
        let memory = self.memory();
        let base = memory.base();
        let place = base + rel.r_offset();
        let r_addend = rel.read_addend(memory, place)?;
        let mut provider = None;

        match r_type {
            value if Arch::DTPOFF == value => {
                let symbol_value = if r_sym == 0 {
                    0
                } else {
                    let symbol = match self.tls_def(rel) {
                        Ok(symbol) => symbol,
                        Err(outcome) => return Ok(outcome),
                    };
                    provider = Some(symbol.provider);
                    symbol.offset
                };
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
                let tls = if r_sym == 0 {
                    self.core.tls()
                } else {
                    let symbol = match self.tls_def(rel) {
                        Ok(symbol) => symbol,
                        Err(outcome) => return Ok(outcome),
                    };
                    provider = Some(symbol.provider);
                    Some(symbol.module)
                };
                let Some(tls) = tls else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsModuleId));
                };
                let mod_id = tls.mod_id();
                unsafe {
                    memory.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(mod_id.get()),
                    )?;
                }
            }
            value if Arch::TPOFF == value => {
                let (tls, symbol_value) = if r_sym == 0 {
                    (self.core.tls(), 0)
                } else {
                    let symbol = match self.tls_def(rel) {
                        Ok(symbol) => symbol,
                        Err(outcome) => return Ok(outcome),
                    };
                    provider = Some(symbol.provider);
                    (Some(symbol.module), symbol.offset)
                };
                let Some(tp_offset) = tls.and_then(ModuleTls::tp_offset) else {
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
                let symbol = self.symbol_entry(rel);
                let request = match self.find_symdef(&symbol) {
                    None => {
                        return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                    }
                    Some(symdef) if symdef.is_weak_undef() => TlsDescRequest::UndefinedWeak {
                        addend: r_addend as usize,
                    },
                    Some(symdef) => {
                        provider = symdef.provider_id();
                        let (sym, source) = symdef
                            .definition()
                            .expect("defined TLS symbol must retain its provider");
                        let Some(tls) = source.tls() else {
                            return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsModuleId));
                        };
                        TlsDescRequest::Defined {
                            module: tls,
                            offset: VmAddr::new(sym.st_value())
                                .wrapping_add_signed(r_addend)
                                .get(),
                        }
                    }
                };
                let desc = self.core.tls_resolver().bind_tlsdesc(request)?;
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
            }
            _ => unreachable!("handle_tls_reloc called with a non-TLS relocation"),
        }
        self.record_binding(provider);
        Ok(TlsRelocOutcome::Applied)
    }
}
