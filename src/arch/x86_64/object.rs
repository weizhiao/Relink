use crate::{
    RelocationError,
    arch::Architecture,
    elf::ElfRelType,
    object::{
        ObjectReloc,
        layout::{GotEntry, PltEntry, PltGotSection},
    },
    relocation::{RelocAddr, RelocHelper, RelocationHandler, SymbolLookup, reloc_error},
};
use elf::abi::*;

pub(crate) struct ObjectRelocator;

pub(crate) const PLT_ENTRY_SIZE: usize = 16;

pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
    0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25, 0, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

impl ObjectReloc for ObjectRelocator {
    fn relocate<D, PreS, PostS, PreH, PostH>(
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        rel: &ElfRelType,
        pltgot: &mut PltGotSection,
    ) -> crate::Result<()>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let r_sym = rel.r_symbol();
        let r_type = rel.r_type();
        let base = helper.core.base_addr();
        let segments = helper.core.segments();
        let append = rel.r_addend(base.into_inner());
        let offset = rel.r_offset();
        let p = base.offset(rel.r_offset());
        let unknown_symbol = || {
            reloc_error(
                rel,
                crate::RelocationFailureReason::UnknownSymbol,
                helper.core,
            )
        };
        let conversion_error = || {
            reloc_error(
                rel,
                crate::RelocationFailureReason::IntegralConversionOutOfRange,
                helper.core,
            )
        };
        let value_error = |err| match err {
            RelocationError::UnsupportedRelocationType => unknown_symbol(),
            RelocationError::IntegerConversionOverflow => conversion_error(),
            _ => unreachable!("unexpected relocation error from value computation"),
        };
        let write_relocation_target = |target| {
            <Architecture as crate::relocation::RelocationValueProvider>::relocation_value(
                r_type,
                target,
                append,
                p.into_inner(),
                |_| {},
                |value| segments.write(offset, value),
                |value| segments.write(offset, value),
                |value| segments.write(offset, value),
            )
        };

        match r_type as _ {
            R_X86_64_NONE => {}
            R_X86_64_64 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(unknown_symbol());
                };
                write_relocation_target(sym.into_inner()).map_err(value_error)?;
            }
            R_X86_64_PC32 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(unknown_symbol());
                };
                write_relocation_target(sym.into_inner()).map_err(value_error)?;
            }
            R_X86_64_PLT32 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(unknown_symbol());
                };
                match write_relocation_target(sym.into_inner()) {
                    Ok(()) => {}
                    Err(RelocationError::UnsupportedRelocationType) => return Err(unknown_symbol()),
                    Err(RelocationError::IntegerConversionOverflow) => {
                        let plt_entry = pltgot.add_plt_entry(r_sym);
                        let plt_entry_addr = match plt_entry {
                            PltEntry::Occupied(plt_entry_addr) => plt_entry_addr,
                            PltEntry::Vacant { plt, mut got } => {
                                let plt_entry_addr = RelocAddr::from_ptr(plt.as_ptr());
                                got.update(sym);
                                let call_offset = got
                                    .get_addr()
                                    .relative_to(plt_entry_addr.into_inner())
                                    .relative_to(10);
                                let call_offset_val = call_offset
                                    .try_into_sword32()
                                    .map_err(|_| conversion_error())?;
                                plt[6..10].copy_from_slice(&call_offset_val.to_ne_bytes());
                                plt_entry_addr
                            }
                        };
                        write_relocation_target(plt_entry_addr.into_inner())
                            .map_err(value_error)?;
                    }
                    Err(_) => unreachable!("unexpected relocation error from value computation"),
                }
            }
            R_X86_64_GOTPCREL => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(unknown_symbol());
                };
                let got_entry = pltgot.add_got_entry(r_sym);
                let got_entry_addr = match got_entry {
                    GotEntry::Occupied(got_entry_addr) => got_entry_addr,
                    GotEntry::Vacant(mut got) => {
                        got.update(sym);
                        got.get_addr()
                    }
                };
                write_relocation_target(got_entry_addr.into_inner()).map_err(value_error)?;
            }
            R_X86_64_32 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(unknown_symbol());
                };
                write_relocation_target(sym.into_inner()).map_err(value_error)?;
            }
            R_X86_64_32S => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(unknown_symbol());
                };
                write_relocation_target(sym.into_inner()).map_err(value_error)?;
            }
            _ => return Err(unknown_symbol()),
        }

        Ok(())
    }

    fn needs_got(rel_type: u32) -> bool {
        matches!(rel_type, R_X86_64_GOTPCREL | R_X86_64_PLT32)
    }

    fn needs_plt(rel_type: u32) -> bool {
        rel_type == R_X86_64_PLT32
    }
}
