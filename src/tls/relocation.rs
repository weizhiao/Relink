#[cfg(feature = "tls")]
mod enabled {
    use super::super::defs::{TlsDescDynamicArg, TlsIndex};
    use crate::{
        arch::*,
        elf::ElfRelType,
        relocation::{RelocAddr, RelocHelper, RelocValue, RelocationHandler, SymbolLookup},
    };
    use alloc::boxed::Box;

    #[inline]
    pub(crate) fn lookup_tls_get_addr(name: &str, tls_get_addr: RelocAddr) -> Option<*const ()> {
        (name == "__tls_get_addr").then_some(tls_get_addr.as_ptr())
    }

    #[inline]
    pub(crate) fn is_tlsdesc_relocation(r_type: u32) -> bool {
        REL_TLSDESC != 0 && r_type == REL_TLSDESC
    }

    #[inline]
    pub(crate) fn is_tls_relocation(r_type: u32) -> bool {
        r_type == REL_DTPOFF
            || r_type == REL_DTPMOD
            || r_type == REL_TPOFF
            || is_tlsdesc_relocation(r_type)
    }

    pub(crate) fn handle_tls_reloc<D, PreS, PostS, PreH, PostH>(
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        rel: &ElfRelType,
    ) -> bool
    where
        D: 'static,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let r_type = rel.r_type() as u32;
        let r_sym = rel.r_symbol();
        let r_addend = rel.r_addend(helper.core.segments().base_addr().into_inner());
        let segments = helper.core.segments();

        match r_type {
            REL_DTPOFF => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let tls_val = RelocValue::new(symdef.sym.unwrap().st_value() as usize)
                        .addend(r_addend)
                        .relative_to(TLS_DTV_OFFSET);
                    segments.write(rel.r_offset(), tls_val);
                    return true;
                }
            }
            REL_DTPMOD => {
                let mod_id = if r_sym == 0 {
                    helper.core.tls_mod_id()
                } else if let Some(symdef) = helper.find_symdef(r_sym) {
                    symdef.lib.tls_mod_id()
                } else {
                    None
                };

                if let Some(mod_id) = mod_id {
                    segments.write(rel.r_offset(), RelocValue::new(mod_id));
                    return true;
                }
            }
            REL_TPOFF => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let sym = symdef.sym.unwrap();
                    if let Some(tp_offset) = symdef.lib.tls_tp_offset() {
                        let tls_val =
                            RelocValue::new((tp_offset + sym.st_value() as isize) as usize)
                                .addend(r_addend);
                        segments.write(rel.r_offset(), tls_val);
                        return true;
                    }
                }
            }
            REL_TLSDESC if REL_TLSDESC != 0 => {
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let sym = symdef.sym.unwrap();
                    if let Some(tp_offset) = symdef.lib.tls_tp_offset() {
                        let tpoff = RelocValue::new((tp_offset + sym.st_value() as isize) as usize)
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
        relocation::{RelocAddr, RelocHelper, RelocationHandler, SymbolLookup},
    };

    #[inline]
    pub(crate) fn lookup_tls_get_addr(_name: &str, _tls_get_addr: RelocAddr) -> Option<*const ()> {
        None
    }

    #[inline]
    pub(crate) fn is_tlsdesc_relocation(_r_type: u32) -> bool {
        false
    }

    #[inline]
    pub(crate) fn is_tls_relocation(_r_type: u32) -> bool {
        false
    }

    #[inline]
    pub(crate) fn handle_tls_reloc<D, PreS, PostS, PreH, PostH>(
        _helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        _rel: &ElfRelType,
    ) -> bool
    where
        D: 'static,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        false
    }
}

#[cfg(not(feature = "tls"))]
pub(crate) use disabled::{
    handle_tls_reloc, is_tls_relocation, is_tlsdesc_relocation, lookup_tls_get_addr,
};
#[cfg(feature = "tls")]
pub(crate) use enabled::{
    handle_tls_reloc, is_tls_relocation, is_tlsdesc_relocation, lookup_tls_get_addr,
};
