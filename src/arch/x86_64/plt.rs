//! RIP-relative operands in linker-generated x86-64 PLT entries.

use crate::{LinkerError, Result};

const ENDBR64: &[u8] = &[0xf3, 0x0f, 0x1e, 0xfa];

pub(super) fn visit_displacements(
    name: &[u8],
    entry_size: usize,
    bytes: &[u8],
    mut visit: impl FnMut(usize, i32) -> Result<()>,
) -> Result<()> {
    // LLD leaves sh_entsize zero. GNU ld supplies the stride explicitly.
    let default_size = match name {
        b".plt.got" | b".plt.bnd" if !bytes.starts_with(ENDBR64) => 8,
        b".plt" | b".plt.sec" | b".plt.got" | b".plt.bnd" | b".iplt" => 16,
        _ => return Ok(()),
    };
    let stride = if entry_size == 0 {
        default_size
    } else {
        entry_size
    };
    if !bytes.len().is_multiple_of(stride) {
        return Err(LinkerError::metadata_rewrite("incomplete x86-64 PLT entry").into());
    }
    for (index, entry) in bytes.chunks_exact(stride).enumerate() {
        let mut code = entry.strip_prefix(ENDBR64).unwrap_or(entry);
        let mut visit_field = |code: &[u8], displacement: [u8; 4]| {
            let offset = index * stride + (entry.len() - code.len()) + 2;
            visit(offset, i32::from_le_bytes(displacement))
        };

        // PLT0 pushes the context from GOT[1] and jumps through GOT[2].
        if let [0xff, 0x35, a, b, c, d, rest @ ..] = code {
            visit_field(code, [*a, *b, *c, *d])?;
            code = rest;
        }
        code = code.strip_prefix(&[0xf2]).unwrap_or(code); // optional BND prefix
        match code {
            [0xff, 0x25, a, b, c, d, ..] => visit_field(code, [*a, *b, *c, *d])?,
            // A split IBT PLT has a resolver entry that pushes the relocation
            // index and branches back to PLT0 within the same section.
            [0x68, _, _, _, _, 0xe9, ..] | [0x68, _, _, _, _, 0xf2, 0xe9, ..] => {}
            _ => return Err(LinkerError::metadata_rewrite("unsupported x86-64 PLT entry").into()),
        }
    }
    Ok(())
}
