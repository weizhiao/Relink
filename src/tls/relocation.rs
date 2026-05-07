#[cfg(feature = "tls")]
mod enabled {
    use super::super::defs::{TlsDescDynamicArg, TlsIndex};
    use crate::{
        arch::{TLS_DTV_OFFSET, tlsdesc_resolver_dynamic, tlsdesc_resolver_static},
        elf::ElfRelType,
        relocation::{
            RelocAddr, RelocHelper, RelocValue, RelocationArch, RelocationHandler, SymbolLookup,
        },
    };
    use alloc::boxed::Box;

    #[inline]
    pub(crate) fn lookup_tls_get_addr(name: &str, tls_get_addr: RelocAddr) -> Option<*const ()> {
        (name == "__tls_get_addr").then_some(tls_get_addr.as_ptr())
    }

    pub(crate) fn handle_tls_reloc<D, Arch, PreS, PostS, PreH, PostH>(
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        rel: &ElfRelType,
    ) -> bool
    where
        D: 'static,
        Arch: RelocationArch,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let r_type = rel.r_type();
        let r_sym = rel.r_symbol();
        let r_addend = rel.r_addend(helper.core.segments().base_addr().into_inner());
        let segments = helper.core.segments();

        match r_type {
            value if value == Arch::DTPOFF => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let tls_val = RelocValue::new(symdef.sym.unwrap().st_value() as usize)
                        .addend(r_addend)
                        .relative_to(TLS_DTV_OFFSET);
                    segments.write(rel.r_offset(), tls_val);
                    return true;
                }
            }
            value if value == Arch::DTPMOD => {
                let mod_id = if r_sym == 0 {
                    helper.core.tls_mod_id()
                } else if let Some(symdef) = helper.find_symdef(r_sym) {
                    symdef.lib.tls_mod_id()
                } else {
                    None
                };

                if let Some(mod_id) = mod_id {
                    segments.write(rel.r_offset(), RelocValue::new(mod_id.get()));
                    return true;
                }
            }
            value if value == Arch::TPOFF => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let sym = symdef.sym.unwrap();
                    if let Some(tp_offset) = symdef.lib.tls_tp_offset() {
                        let tls_val =
                            RelocValue::new((tp_offset.get() + sym.st_value() as isize) as usize)
                                .addend(r_addend);
                        segments.write(rel.r_offset(), tls_val);
                        return true;
                    }
                }
            }
            value if Arch::is_tlsdesc(value) => {
                // TLSDESC writes a host function pointer into the slot
                // (`tlsdesc_resolver_static` / `_dynamic`). That stub only
                // makes sense when the relocated module shares the host's
                // ABI and CPU; cross-architecture loaders must defer this
                // class of relocation to a custom `RelocationHandler`.
                if !Arch::SUPPORTS_NATIVE_RUNTIME {
                    return false;
                }
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let sym = symdef.sym.unwrap();
                    if let Some(tp_offset) = symdef.lib.tls_tp_offset() {
                        let tpoff =
                            RelocValue::new((tp_offset.get() + sym.st_value() as isize) as usize)
                                .addend(r_addend);
                        segments.write(
                            rel.r_offset(),
                            RelocAddr::from_ptr(tlsdesc_resolver_static as *const ()),
                        );
                        segments.write(rel.r_offset() + 8, tpoff);
                        return true;
                    }

                    if let Some(mod_id) = symdef.lib.tls_mod_id() {
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

                        segments.write(
                            rel.r_offset(),
                            RelocAddr::from_ptr(tlsdesc_resolver_dynamic as *const ()),
                        );
                        segments.write(rel.r_offset() + 8, arg_ptr);
                        return true;
                    }
                }
            }
            _ => return false,
        }
        false
    }
}

#[cfg(not(feature = "tls"))]
mod disabled {
    use crate::{
        elf::ElfRelType,
        relocation::{RelocAddr, RelocHelper, RelocationArch, RelocationHandler, SymbolLookup},
    };

    #[inline]
    pub(crate) fn lookup_tls_get_addr(_name: &str, _tls_get_addr: RelocAddr) -> Option<*const ()> {
        None
    }

    #[inline]
    pub(crate) fn handle_tls_reloc<D, Arch, PreS, PostS, PreH, PostH>(
        _helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        _rel: &ElfRelType,
    ) -> bool
    where
        D: 'static,
        Arch: RelocationArch,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        false
    }
}

#[cfg(not(feature = "tls"))]
pub(crate) use disabled::{handle_tls_reloc, lookup_tls_get_addr};
#[cfg(feature = "tls")]
pub(crate) use enabled::{handle_tls_reloc, lookup_tls_get_addr};
