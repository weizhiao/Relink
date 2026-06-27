use crate::RelocReason;

pub(crate) enum TlsRelocOutcome {
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    Applied,
    Failed(RelocReason),
}

#[cfg(feature = "tls")]
mod enabled {
    use super::super::defs::TlsIndex;
    use super::TlsRelocOutcome;
    use crate::{
        RelocReason, Result,
        elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord},
        memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
        observer::{RelocationObserver, TlsDescBindingRequest, TlsDescValue},
        relocation::{RelocHelper, RelocationArch, RelocationHandler},
        tls::TlsResolver,
    };

    pub(crate) enum TlsDescResolution {
        Resolved(TlsDescValue),
        Failed(RelocReason),
    }

    impl<'find, D, Arch, R, Tls, PreH, PostH, Obs, H>
        RelocHelper<'find, D, Arch, R, Tls, PreH, PostH, Obs, H>
    where
        D: 'static,
        Arch: RelocationArch,
        R: RegionAccess,
        Tls: TlsResolver<Arch>,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        #[inline]
        pub(crate) fn resolve_tlsdesc(
            &mut self,
            request: TlsDescBindingRequest,
        ) -> Result<TlsDescResolution> {
            let sym_value = request.symbol_value();
            let addend = request.addend();

            if let Some(tp_offset) = request.tp_offset() {
                let tpoff = VmAddr::new((tp_offset.get() + sym_value as isize) as usize)
                    .wrapping_add_signed(addend);
                return Ok(TlsDescResolution::Resolved(Tls::bind_static_tlsdesc(
                    tpoff.get(),
                )?));
            }

            if let Some(module_id) = request.module_id() {
                let offset = VmAddr::new(sym_value)
                    .wrapping_add_signed(addend)
                    .get()
                    .wrapping_sub(Arch::TLS_DTV_OFFSET);
                return Ok(TlsDescResolution::Resolved(Tls::bind_dynamic_tlsdesc(
                    TlsIndex {
                        ti_module: module_id,
                        ti_offset: offset,
                    },
                )?));
            }

            Ok(TlsDescResolution::Failed(RelocReason::MissingTlsModuleId))
        }
    }

    pub(crate) fn handle_tls_reloc<D, Arch, R, Tls, PreH, PostH, Obs, H>(
        helper: &mut RelocHelper<'_, D, Arch, R, Tls, PreH, PostH, Obs, H>,
        rel: &ElfRelType<Arch>,
    ) -> Result<TlsRelocOutcome>
    where
        D: 'static,
        Arch: RelocationArch,
        R: RegionAccess,
        Tls: TlsResolver<Arch>,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
        <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
    {
        let r_type = rel.r_type();
        let r_sym = rel.r_symbol();
        let segments = helper.core.segments();
        let base = segments.base();
        let place = base + rel.r_offset();
        let r_addend = rel.read_addend(segments, place)?;

        match r_type {
            value if value == Arch::DTPOFF => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let Some(sym) = symdef.symbol() else {
                        return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                    };
                    let tls_val = VmAddr::new(sym.st_value())
                        .wrapping_add_signed(r_addend)
                        .get()
                        .wrapping_sub(Arch::TLS_DTV_OFFSET);
                    unsafe {
                        segments.write_value(
                            place,
                            <Arch::Layout as ElfLayout>::Word::from_usize(tls_val),
                        )?;
                    }
                    Ok(TlsRelocOutcome::Applied)
                } else {
                    Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol))
                }
            }
            value if value == Arch::DTPMOD => {
                let Some(tls) = (if r_sym == 0 {
                    Some(helper.core.tls())
                } else {
                    helper.find_symdef(r_sym).map(|symdef| symdef.tls())
                }) else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                };
                let Some(mod_id) = tls.mod_id() else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsModuleId));
                };
                unsafe {
                    segments.write_value(
                        place,
                        <Arch::Layout as ElfLayout>::Word::from_usize(mod_id.get()),
                    )?;
                }
                Ok(TlsRelocOutcome::Applied)
            }
            value if value == Arch::TPOFF => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let Some(sym) = symdef.symbol() else {
                        return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                    };
                    if let Some(tp_offset) = symdef.tls().tp_offset() {
                        let tls_val =
                            VmAddr::new((tp_offset.get() + sym.st_value() as isize) as usize)
                                .wrapping_add_signed(r_addend);
                        unsafe {
                            segments.write_value(
                                place,
                                <Arch::Layout as ElfLayout>::Word::from_usize(tls_val.get()),
                            )?;
                        }
                        Ok(TlsRelocOutcome::Applied)
                    } else {
                        Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsTpOffset))
                    }
                } else {
                    Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol))
                }
            }
            value if Arch::is_tlsdesc(value) => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let Some(sym) = symdef.symbol() else {
                        return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                    };
                    let sym_value = sym.st_value();
                    let tls = symdef.tls();
                    let tls_mod_id = tls.mod_id();
                    let tls_tp_offset = tls.tp_offset();
                    let request =
                        TlsDescBindingRequest::new(sym_value, r_addend, tls_mod_id, tls_tp_offset);
                    match helper.resolve_tlsdesc(request)? {
                        TlsDescResolution::Resolved(desc) => {
                            unsafe {
                                segments.write_value(
                                    place,
                                    <Arch::Layout as ElfLayout>::Word::from_usize(
                                        desc.resolver().get(),
                                    ),
                                )?;
                                segments.write_value(
                                    place + VmOffset::new(8),
                                    <Arch::Layout as ElfLayout>::Word::from_usize(desc.arg()),
                                )?;
                            }
                            Ok(TlsRelocOutcome::Applied)
                        }
                        TlsDescResolution::Failed(reason) => Ok(TlsRelocOutcome::Failed(reason)),
                    }
                } else {
                    Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol))
                }
            }
            _ => unreachable!("handle_tls_reloc called with a non-TLS relocation"),
        }
    }
}

#[cfg(not(feature = "tls"))]
mod disabled {
    use super::TlsRelocOutcome;
    use crate::{
        RelocReason, Result,
        elf::{ElfRelEntry, ElfRelType},
        memory::RegionAccess,
        observer::RelocationObserver,
        relocation::{RelocHelper, RelocationArch, RelocationHandler},
        tls::TlsResolver,
    };

    #[inline]
    pub(crate) fn handle_tls_reloc<D, Arch, R, Tls, PreH, PostH, Obs>(
        _helper: &mut RelocHelper<'_, D, Arch, R, Tls, PreH, PostH, Obs>,
        rel: &ElfRelType<Arch>,
    ) -> Result<TlsRelocOutcome>
    where
        D: 'static,
        Arch: RelocationArch,
        R: RegionAccess,
        Tls: TlsResolver<Arch>,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        debug_assert!(Arch::is_tls(rel.r_type()));
        Ok(TlsRelocOutcome::Failed(RelocReason::TlsDisabled))
    }
}

#[cfg(not(feature = "tls"))]
pub(crate) use disabled::handle_tls_reloc;
#[cfg(feature = "tls")]
pub(crate) use enabled::handle_tls_reloc;
