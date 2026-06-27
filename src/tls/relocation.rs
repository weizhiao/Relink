use super::defs::TlsIndex;
use crate::{
    RelocReason, Result,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfSymbol, ElfWord},
    image::Module,
    memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
    observer::RelocationObserver,
    relocation::{RelocHelper, RelocationArch, RelocationHandler, SymDef},
    tls::TlsResolver,
};

pub(crate) enum TlsRelocOutcome {
    Applied,
    Failed(RelocReason),
}

struct TlsDefinedSymbol<'a, Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> {
    symbol: &'a ElfSymbol<Arch::Layout>,
    source: &'a dyn Module<Arch, Tls>,
}

impl<'find, D, Arch, R, Tls, PreH, PostH, Obs, H, Memory>
    RelocHelper<'find, D, Arch, R, Tls, PreH, PostH, Obs, H, Memory>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    PreH: RelocationHandler<Arch> + ?Sized,
    PostH: RelocationHandler<Arch> + ?Sized,
    Obs: RelocationObserver<Arch> + ?Sized,
    Memory: ImageMemory,
    <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
{
    #[inline]
    fn defined_tls_symbol(
        &self,
        rel: &ElfRelType<Arch>,
    ) -> core::result::Result<TlsDefinedSymbol<'_, Arch, Tls>, TlsRelocOutcome> {
        let symbol = self.symbol_entry(rel);
        match self.find_symdef(&symbol) {
            Some(SymDef::Defined { symbol, source }) => Ok(TlsDefinedSymbol { symbol, source }),
            Some(SymDef::WeakUndef) => Err(TlsRelocOutcome::Applied),
            None => Err(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol)),
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
                let defined = match self.defined_tls_symbol(rel) {
                    Ok(defined) => defined,
                    Err(outcome) => return Ok(outcome),
                };
                let tls_val = VmAddr::new(defined.symbol.st_value())
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
                    let defined = match self.defined_tls_symbol(rel) {
                        Ok(defined) => defined,
                        Err(outcome) => return Ok(outcome),
                    };
                    defined.source.tls()
                };
                let Some(mod_id) = tls.mod_id() else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsModuleId));
                };
                unsafe {
                    memory.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(mod_id.get()),
                    )?;
                }
                Ok(TlsRelocOutcome::Applied)
            }
            value if value == Arch::TPOFF => {
                let defined = match self.defined_tls_symbol(rel) {
                    Ok(defined) => defined,
                    Err(outcome) => return Ok(outcome),
                };
                let tls = defined.source.tls();
                let Some(tp_offset) = tls.tp_offset() else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsTpOffset));
                };
                let tls_val =
                    VmAddr::new((tp_offset.get() + defined.symbol.st_value() as isize) as usize)
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
                let desc = match self.find_symdef(&symbol) {
                    Some(SymDef::WeakUndef) => Tls::bind_undefweak_tlsdesc(r_addend as usize)?,
                    None => {
                        return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                    }
                    Some(SymDef::Defined {
                        symbol: sym,
                        source,
                    }) => {
                        let tls = source.tls();
                        if let Some(tp_offset) = tls.tp_offset() {
                            let tpoff =
                                VmAddr::new((tp_offset.get() + sym.st_value() as isize) as usize)
                                    .wrapping_add_signed(r_addend);
                            Tls::bind_static_tlsdesc(tpoff.get())?
                        } else if let Some(module_id) = tls.mod_id() {
                            let offset = VmAddr::new(sym.st_value())
                                .wrapping_add_signed(r_addend)
                                .get()
                                .wrapping_sub(Arch::TLS_DTV_OFFSET);
                            Tls::bind_dynamic_tlsdesc(TlsIndex {
                                ti_module: module_id,
                                ti_offset: offset,
                            })?
                        } else {
                            return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsModuleId));
                        }
                    }
                };
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
