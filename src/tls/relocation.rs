#[cfg(feature = "tls")]
mod enabled {
    use super::super::defs::{TlsDescDynamicArg, TlsIndex};
    use crate::{
        FailureReason,
        arch::{tlsdesc_resolver_dynamic, tlsdesc_resolver_static},
        elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord},
        relocation::{
            RelocAddr, RelocHelper, RelocValue, RelocationArch, RelocationHandler, SymbolLookup,
        },
        segment::ElfSegments,
    };
    use alloc::boxed::Box;

    #[inline]
    pub(crate) fn lookup_tls_get_addr(name: &str, tls_get_addr: RelocAddr) -> Option<*const ()> {
        (name == "__tls_get_addr").then_some(tls_get_addr.as_ptr())
    }

    #[inline]
    fn write_tls_word<Arch: RelocationArch>(segments: &ElfSegments, offset: usize, value: usize) {
        segments.write(
            offset,
            RelocValue::new(<Arch::Layout as ElfLayout>::Word::from_usize(value)),
        );
    }

    pub(crate) fn handle_tls_reloc<D, Arch, PreS, PostS, PreH, PostH>(
        helper: &mut RelocHelper<'_, D, Arch, PreS, PostS, PreH, PostH>,
        rel: &ElfRelType<Arch>,
    ) -> Result<(), FailureReason>
    where
        D: 'static,
        Arch: RelocationArch,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
    {
        let r_type = rel.r_type();
        let r_sym = rel.r_symbol();
        let r_addend = rel.r_addend(helper.core.segments().base_addr().into_inner());
        let segments = helper.core.segments();

        match r_type {
            value if value == Arch::DTPOFF => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let Some(sym) = symdef.symbol() else {
                        return Err(FailureReason::UnknownSymbol);
                    };
                    let tls_val = RelocValue::new(sym.st_value())
                        .addend(r_addend)
                        .relative_to(Arch::TLS_DTV_OFFSET);
                    write_tls_word::<Arch>(segments, rel.r_offset(), tls_val.into_inner());
                    return Ok(());
                }
                return Err(FailureReason::UnknownSymbol);
            }
            value if value == Arch::DTPMOD => {
                let Some(mod_id) = (if r_sym == 0 {
                    Some(helper.core.tls_mod_id())
                } else if let Some(symdef) = helper.find_symdef(r_sym) {
                    Some(symdef.tls_mod_id())
                } else {
                    None
                }) else {
                    return Err(FailureReason::UnknownSymbol);
                };
                let Some(mod_id) = mod_id else {
                    return Err(FailureReason::TlsModuleIdUnavailable);
                };
                write_tls_word::<Arch>(segments, rel.r_offset(), mod_id.get());
                return Ok(());
            }
            value if value == Arch::TPOFF => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let Some(sym) = symdef.symbol() else {
                        return Err(FailureReason::UnknownSymbol);
                    };
                    if let Some(tp_offset) = symdef.tls_tp_offset() {
                        let tls_val =
                            RelocValue::new((tp_offset.get() + sym.st_value() as isize) as usize)
                                .addend(r_addend);
                        write_tls_word::<Arch>(segments, rel.r_offset(), tls_val.into_inner());
                        return Ok(());
                    }
                    return Err(FailureReason::TlsTpOffsetUnavailable);
                }
                return Err(FailureReason::UnknownSymbol);
            }
            value if Arch::is_tlsdesc(value) => {
                // TLSDESC writes a host function pointer into the slot
                // (`tlsdesc_resolver_static` / `_dynamic`). That stub only
                // makes sense when the relocated module shares the host's
                // ABI and CPU; cross-architecture loaders must defer this
                // class of relocation to a custom `RelocationHandler`.
                if !Arch::SUPPORTS_NATIVE_RUNTIME {
                    return Err(FailureReason::TlsNativeRuntimeUnsupported);
                }
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let Some(sym) = symdef.symbol() else {
                        return Err(FailureReason::UnknownSymbol);
                    };
                    if let Some(tp_offset) = symdef.tls_tp_offset() {
                        let tpoff =
                            RelocValue::new((tp_offset.get() + sym.st_value() as isize) as usize)
                                .addend(r_addend);
                        write_tls_word::<Arch>(
                            segments,
                            rel.r_offset(),
                            tlsdesc_resolver_static as *const () as usize,
                        );
                        write_tls_word::<Arch>(segments, rel.r_offset() + 8, tpoff.into_inner());
                        return Ok(());
                    }

                    if let Some(mod_id) = symdef.tls_mod_id() {
                        let offset = RelocValue::new(sym.st_value() as usize).addend(r_addend);
                        let dynamic_arg = Box::new(TlsDescDynamicArg {
                            tls_get_addr: helper.tls_get_addr.into_inner(),
                            ti: TlsIndex {
                                ti_module: mod_id,
                                ti_offset: offset.into_inner(),
                            },
                        });

                        let arg_ptr = RelocAddr::from_ptr(dynamic_arg.as_ref());
                        helper.tls_desc_args.push(dynamic_arg);

                        write_tls_word::<Arch>(
                            segments,
                            rel.r_offset(),
                            tlsdesc_resolver_dynamic as *const () as usize,
                        );
                        write_tls_word::<Arch>(segments, rel.r_offset() + 8, arg_ptr.into_inner());
                        return Ok(());
                    }
                    return Err(FailureReason::TlsModuleIdUnavailable);
                }
                return Err(FailureReason::UnknownSymbol);
            }
            _ => unreachable!("handle_tls_reloc called with a non-TLS relocation"),
        }
    }
}

#[cfg(not(feature = "tls"))]
mod disabled {
    use crate::{
        FailureReason,
        elf::{ElfRelEntry, ElfRelType},
        relocation::{RelocAddr, RelocHelper, RelocationArch, RelocationHandler, SymbolLookup},
    };

    #[inline]
    pub(crate) fn lookup_tls_get_addr(_name: &str, _tls_get_addr: RelocAddr) -> Option<*const ()> {
        None
    }

    #[inline]
    pub(crate) fn handle_tls_reloc<D, Arch, PreS, PostS, PreH, PostH>(
        _helper: &mut RelocHelper<'_, D, Arch, PreS, PostS, PreH, PostH>,
        rel: &ElfRelType<Arch>,
    ) -> Result<(), FailureReason>
    where
        D: 'static,
        Arch: RelocationArch,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
    {
        debug_assert!(Arch::is_tls(rel.r_type()));
        Err(FailureReason::TlsDisabled)
    }
}

#[cfg(not(feature = "tls"))]
pub(crate) use disabled::{handle_tls_reloc, lookup_tls_get_addr};
#[cfg(feature = "tls")]
pub(crate) use enabled::{handle_tls_reloc, lookup_tls_get_addr};
