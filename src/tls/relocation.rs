use super::defs::{ModuleTls, TlsDescRequest};
use crate::{
    ByteRepr, RelocReason, Result,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord},
    memory::{ImageMemory, ImageMemoryExt, RegionAccess, VmAddr, VmOffset},
    observer::RelocationObserver,
    relocation::{RelocHelper, RelocationArch, SymDef},
    tls::TlsResolver,
};

pub(crate) enum TlsRelocOutcome {
    Applied,
    Failed(RelocReason),
}

impl<'find, D, Arch, R, Tls, Obs, H, Memory> RelocHelper<'find, D, Arch, R, Tls, Obs, H, Memory>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    Obs: RelocationObserver<Arch> + ?Sized,
    Memory: ImageMemory,
    <Arch::Layout as ElfLayout>::Word: ByteRepr,
{
    #[inline]
    fn defined_tls_symbol(
        &self,
        rel: &ElfRelType<Arch>,
    ) -> core::result::Result<SymDef<'_, Arch, Tls>, TlsRelocOutcome> {
        let symbol = self.symbol_entry(rel);
        let Some(symdef) = self.find_symdef(&symbol) else {
            return Err(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
        };
        if symdef.is_weak_undef() {
            Err(TlsRelocOutcome::Applied)
        } else {
            Ok(symdef)
        }
    }

    pub(crate) fn handle_tls_reloc(&mut self, rel: &ElfRelType<Arch>) -> Result<TlsRelocOutcome> {
        let r_type = rel.r_type();
        let r_sym = rel.r_symbol();
        let memory = self.memory();
        let base = memory.base();
        let place = base + rel.r_offset();
        let r_addend = rel.read_addend(memory, place)?;

        match r_type {
            value if value == Arch::DTPOFF => {
                let symdef = match self.defined_tls_symbol(rel) {
                    Ok(symdef) => symdef,
                    Err(outcome) => return Ok(outcome),
                };
                let (symbol, _) = symdef
                    .parts()
                    .expect("defined TLS symbol must retain its provider");
                let tls_val = VmAddr::new(symbol.st_value())
                    .wrapping_add_signed(r_addend)
                    .get()
                    .wrapping_sub(Arch::TLS_DTV_OFFSET);
                unsafe {
                    memory.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(tls_val),
                    )?;
                }
                Ok(TlsRelocOutcome::Applied)
            }
            value if value == Arch::DTPMOD => {
                let tls = if r_sym == 0 {
                    self.core.tls()
                } else {
                    let symdef = match self.defined_tls_symbol(rel) {
                        Ok(symdef) => symdef,
                        Err(outcome) => return Ok(outcome),
                    };
                    symdef
                        .parts()
                        .expect("defined TLS symbol must retain its provider")
                        .1
                        .tls()
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
                Ok(TlsRelocOutcome::Applied)
            }
            value if value == Arch::TPOFF => {
                let symdef = match self.defined_tls_symbol(rel) {
                    Ok(symdef) => symdef,
                    Err(outcome) => return Ok(outcome),
                };
                let (symbol, source) = symdef
                    .parts()
                    .expect("defined TLS symbol must retain its provider");
                let Some(tp_offset) = source.tls().and_then(ModuleTls::tp_offset) else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsTpOffset));
                };
                let tls_val = VmAddr::new((tp_offset.get() + symbol.st_value() as isize) as usize)
                    .wrapping_add_signed(r_addend);
                unsafe {
                    memory.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(tls_val.get()),
                    )?;
                }
                Ok(TlsRelocOutcome::Applied)
            }
            value if Arch::is_tlsdesc(value) => {
                let symbol = self.symbol_entry(rel);
                let request = match self.find_symdef(&symbol) {
                    None => {
                        return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                    }
                    Some(symdef) if symdef.is_weak_undef() => TlsDescRequest::UndefinedWeak {
                        addend: r_addend as usize,
                    },
                    Some(symdef) => {
                        let (sym, source) = symdef
                            .parts()
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
                unsafe {
                    memory.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(desc.resolver().get()),
                    )?;
                    memory.write_value(
                        place + VmOffset::new(8),
                        <Arch::Layout as ElfLayout>::Word::from_usize(desc.arg()),
                    )?;
                }
                Ok(TlsRelocOutcome::Applied)
            }
            _ => unreachable!("handle_tls_reloc called with a non-TLS relocation"),
        }
    }
}
