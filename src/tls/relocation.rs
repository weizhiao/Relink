use crate::RelocReason;

pub(crate) enum TlsRelocOutcome {
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    Applied,
    Failed(RelocReason),
}

#[cfg(feature = "tls")]
mod enabled {
    use super::super::defs::{TlsDescDynamicArg, TlsIndex};
    use super::TlsRelocOutcome;
    use crate::{
        RelocReason, Result,
        arch::{tlsdesc_resolver_dynamic, tlsdesc_resolver_static},
        elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord},
        observer::{
            RelocationObserver, TlsDescBindingEvent, TlsDescBindingRequest, TlsDescBindingValue,
        },
        os::{RegionAccess, VmAddr, VmOffset},
        relocation::{RelocHelper, RelocValue, RelocationArch, RelocationHandler},
        segment::ElfSegments,
    };
    use alloc::boxed::Box;

    pub(crate) enum TlsDescResolution {
        Resolved(TlsDescBindingValue),
        Failed(RelocReason),
    }

    #[inline]
    pub(crate) fn lookup_tls_get_addr(name: &str, tls_get_addr: VmAddr) -> Option<*const ()> {
        (name == "__tls_get_addr").then_some(tls_get_addr.as_ptr())
    }

    #[inline]
    fn write_tls_word<Arch: RelocationArch, R: RegionAccess>(
        segments: &ElfSegments<R>,
        addr: VmAddr,
        value: usize,
    ) -> Result<()>
    where
        <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
    {
        unsafe {
            segments.write_value(
                addr,
                RelocValue::new(<Arch::Layout as ElfLayout>::Word::from_usize(value)),
            )
        }
    }

    impl<'find, D, Arch, R, PreH, PostH, Obs> RelocHelper<'find, D, Arch, R, PreH, PostH, Obs>
    where
        D: 'static,
        Arch: RelocationArch,
        R: RegionAccess,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        #[inline]
        pub(crate) fn resolve_tlsdesc(
            &mut self,
            rel: &ElfRelType<Arch>,
            request: TlsDescBindingRequest,
        ) -> Result<TlsDescResolution> {
            let mut event = TlsDescBindingEvent::new(self.core, rel, request);
            self.observer.on_tlsdesc_binding(&mut event)?;
            if let Some(value) = event.into_value() {
                return Ok(TlsDescResolution::Resolved(value));
            }
            if !Arch::SUPPORTS_NATIVE_RUNTIME {
                return Ok(TlsDescResolution::Failed(RelocReason::UnknownSymbol));
            }

            let sym_value = request.symbol_value();
            let addend = request.addend();

            if let Some(tp_offset) = request.tp_offset() {
                let tpoff = VmAddr::new((tp_offset.get() + sym_value as isize) as usize)
                    .wrapping_add_signed(addend);
                return Ok(TlsDescResolution::Resolved(TlsDescBindingValue::new(
                    VmAddr::from_ptr(tlsdesc_resolver_static as *const ()),
                    tpoff.get(),
                )));
            }

            if let Some(module_id) = request.module_id() {
                let offset = VmAddr::new(sym_value).wrapping_add_signed(addend);
                let dynamic_arg = Box::new(TlsDescDynamicArg {
                    tls_get_addr: request.tls_get_addr().get(),
                    ti: TlsIndex {
                        ti_module: module_id,
                        ti_offset: offset.get(),
                    },
                });
                let arg_ptr = VmAddr::from_ptr(dynamic_arg.as_ref());
                self.tls_desc_args.push(dynamic_arg);

                return Ok(TlsDescResolution::Resolved(TlsDescBindingValue::new(
                    VmAddr::from_ptr(tlsdesc_resolver_dynamic as *const ()),
                    arg_ptr.get(),
                )));
            }

            Ok(TlsDescResolution::Failed(RelocReason::MissingTlsModuleId))
        }
    }

    pub(crate) fn handle_tls_reloc<D, Arch, R, PreH, PostH, Obs>(
        helper: &mut RelocHelper<'_, D, Arch, R, PreH, PostH, Obs>,
        rel: &ElfRelType<Arch>,
    ) -> Result<TlsRelocOutcome>
    where
        D: 'static,
        Arch: RelocationArch,
        R: RegionAccess,
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
        let r_addend = rel.r_addend(base);

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
                    write_tls_word::<Arch, R>(segments, place, tls_val)?;
                    return Ok(TlsRelocOutcome::Applied);
                }
                return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
            }
            value if value == Arch::DTPMOD => {
                let Some(mod_id) = (if r_sym == 0 {
                    Some(helper.core.tls_mod_id())
                } else if let Some(symdef) = helper.find_symdef(r_sym) {
                    Some(symdef.tls_mod_id())
                } else {
                    None
                }) else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                };
                let Some(mod_id) = mod_id else {
                    return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsModuleId));
                };
                write_tls_word::<Arch, R>(segments, place, mod_id.get())?;
                return Ok(TlsRelocOutcome::Applied);
            }
            value if value == Arch::TPOFF => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let Some(sym) = symdef.symbol() else {
                        return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                    };
                    if let Some(tp_offset) = symdef.tls_tp_offset() {
                        let tls_val =
                            VmAddr::new((tp_offset.get() + sym.st_value() as isize) as usize)
                                .wrapping_add_signed(r_addend);
                        write_tls_word::<Arch, R>(segments, place, tls_val.get())?;
                        return Ok(TlsRelocOutcome::Applied);
                    }
                    return Ok(TlsRelocOutcome::Failed(RelocReason::MissingTlsTpOffset));
                }
                return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
            }
            value if Arch::is_tlsdesc(value) => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let Some(sym) = symdef.symbol() else {
                        return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
                    };
                    let sym_value = sym.st_value();
                    let tls_mod_id = symdef.tls_mod_id();
                    let tls_tp_offset = symdef.tls_tp_offset();
                    let tls_get_addr = helper.tls_get_addr;
                    let request = TlsDescBindingRequest::new(
                        sym_value,
                        r_addend,
                        tls_mod_id,
                        tls_tp_offset,
                        tls_get_addr,
                    );
                    match helper.resolve_tlsdesc(rel, request)? {
                        TlsDescResolution::Resolved(desc) => {
                            write_tls_word::<Arch, R>(segments, place, desc.resolver().get())?;
                            write_tls_word::<Arch, R>(
                                segments,
                                place + VmOffset::new(8),
                                desc.arg(),
                            )?;
                            return Ok(TlsRelocOutcome::Applied);
                        }
                        TlsDescResolution::Failed(reason) => {
                            return Ok(TlsRelocOutcome::Failed(reason));
                        }
                    }
                }
                return Ok(TlsRelocOutcome::Failed(RelocReason::UnknownSymbol));
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
        observer::RelocationObserver,
        os::{RegionAccess, VmAddr},
        relocation::{RelocHelper, RelocationArch, RelocationHandler},
    };

    #[inline]
    pub(crate) fn lookup_tls_get_addr(_name: &str, _tls_get_addr: VmAddr) -> Option<*const ()> {
        None
    }

    #[inline]
    pub(crate) fn handle_tls_reloc<D, Arch, R, PreH, PostH, Obs>(
        _helper: &mut RelocHelper<'_, D, Arch, R, PreH, PostH, Obs>,
        rel: &ElfRelType<Arch>,
    ) -> Result<TlsRelocOutcome>
    where
        D: 'static,
        Arch: RelocationArch,
        R: RegionAccess,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        debug_assert!(Arch::is_tls(rel.r_type()));
        Ok(TlsRelocOutcome::Failed(RelocReason::TlsDisabled))
    }
}

#[cfg(not(feature = "tls"))]
pub(crate) use disabled::{handle_tls_reloc, lookup_tls_get_addr};
#[cfg(feature = "tls")]
pub(crate) use enabled::{handle_tls_reloc, lookup_tls_get_addr};
