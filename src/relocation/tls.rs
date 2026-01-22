use crate::{
    arch::*,
    elf::ElfRelType,
    relocation::{RelocValue, RelocationContext},
};

pub(crate) fn handle_tls_reloc<D>(
    hctx: &RelocationContext<'_, D>,
    rel: &ElfRelType,
    dependency_flags: &mut [bool],
) -> bool {
    let r_type = rel.r_type() as u32;
    let r_sym = rel.r_symbol();
    let r_addend = rel.r_addend(hctx.lib().segments().base());
    let segments = hctx.lib().segments();

    match r_type {
        REL_DTPOFF => {
            if let Some((symdef, idx)) = hctx.find_symdef(r_sym) {
                if let Some(idx) = idx {
                    dependency_flags[idx] = true;
                }
                // Calculate offset within TLS block
                let tls_val = RelocValue::new(symdef.sym.unwrap().st_value() as usize) + r_addend
                    - TLS_DTV_OFFSET;
                segments.write(rel.r_offset(), tls_val);
                return true;
            }
        }
        REL_DTPMOD => {
            let mod_id = if r_sym == 0 {
                hctx.lib().tls_mod_id()
            } else if let Some((symdef, _)) = hctx.find_symdef(r_sym) {
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
            if let Some((symdef, idx)) = hctx.find_symdef(r_sym) {
                if let Some(idx) = idx {
                    dependency_flags[idx] = true;
                }
                let sym = symdef.sym.unwrap();
                if let Some(tp_offset) = symdef.lib.tls_tp_offset() {
                    let tls_val =
                        RelocValue::new((tp_offset + sym.st_value() as isize) as usize) + r_addend;
                    segments.write(rel.r_offset(), tls_val);
                    return true;
                }
            }
        }
        _ => return false,
    }
    false
}
