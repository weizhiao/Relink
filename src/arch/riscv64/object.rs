use crate::{
    RelocReason, Result,
    arch::riscv64::relocation::RiscV64Arch,
    elf::{ElfHashTable, ElfRelType, ElfRelocationType},
    object::layout::{GotEntry, PltEntry, PltGotSection},
    observer::RelocationObserver,
    os::{RegionAccess, VmAddr, VmOffset},
    relocation::{ObjectRelocationArch, RelocHelper, RelocValue, RelocationHandler, reloc_error},
    segment::ElfSegments,
};
use elf::abi::*;
use hashbrown::HashMap;

#[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
pub(crate) const PLT_ENTRY_SIZE: usize = 16;

#[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
    0x17, 0x0e, 0x00, 0x00, // auipc t3, 0
    0x03, 0x3e, 0x0e, 0x00, // ld t3, 0(t3)
    0x67, 0x03, 0x0e, 0x00, // jalr t1, t3, 0
    0x13, 0x00, 0x00, 0x00, // nop
];

#[derive(Copy, Clone)]
enum ImmType {
    U,
    I,
    S,
    B,
    J,
    CB,
    CJ,
}

trait WrappingRelocWord: Copy {
    fn trunc_from_usize(val: usize) -> Self;
    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;
}

macro_rules! impl_wrapping_reloc_word {
    ($($ty:ty),* $(,)?) => {
        $(
            impl WrappingRelocWord for $ty {
                #[inline]
                fn trunc_from_usize(val: usize) -> Self {
                    val as Self
                }

                #[inline]
                fn wrapping_add(self, rhs: Self) -> Self {
                    self.wrapping_add(rhs)
                }

                #[inline]
                fn wrapping_sub(self, rhs: Self) -> Self {
                    self.wrapping_sub(rhs)
                }
            }
        )*
    };
}

impl_wrapping_reloc_word!(u8, u16, u32, u64);

#[derive(Clone, Copy)]
struct Hi20Relocation {
    symbol: usize,
    addend: isize,
    r_type: u32,
}

#[derive(Default)]
#[doc(hidden)]
pub struct RiscV64ObjectRelocationState {
    hi20_cache: HashMap<VmAddr, Hi20Relocation>,
}

impl ObjectRelocationArch for RiscV64Arch {
    type ObjectRelocationState = RiscV64ObjectRelocationState;

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn prepare_object_relocation<D, R, PreH, PostH, Obs, H>(
        state: &mut Self::ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, PreH, PostH, Obs, H>,
        sections: &[&'static [ElfRelType<Self>]],
    ) -> Result<()>
    where
        D: 'static,
        R: RegionAccess,
        H: ElfHashTable<<RiscV64Arch as crate::relocation::RelocationArch>::Layout> + 'static,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
    {
        Self::prepare_object_relocation_impl(state, helper, sections)
    }

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn relocate_object<D, R, PreH, PostH, Obs, H>(
        state: &mut Self::ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, PreH, PostH, Obs, H>,
        rel: &ElfRelType<Self>,
        pltgot: &mut PltGotSection,
    ) -> Result<()>
    where
        D: 'static,
        R: RegionAccess,
        H: ElfHashTable<<RiscV64Arch as crate::relocation::RelocationArch>::Layout> + 'static,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
    {
        Self::relocate_object_impl(state, helper, rel, pltgot)
    }

    #[inline]
    fn object_needs_got(r_type: ElfRelocationType) -> bool {
        Self::object_needs_got_impl(r_type)
    }

    #[inline]
    fn object_needs_plt(r_type: ElfRelocationType) -> bool {
        Self::object_needs_plt_impl(r_type)
    }
}

impl RiscV64Arch {
    pub(crate) fn prepare_object_relocation_impl<D, R, PreH, PostH, Obs, H>(
        state: &mut RiscV64ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, PreH, PostH, Obs, H>,
        sections: &[&'static [ElfRelType<Self>]],
    ) -> Result<()>
    where
        D: 'static,
        R: RegionAccess,
        H: ElfHashTable<<RiscV64Arch as crate::relocation::RelocationArch>::Layout> + 'static,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
    {
        let base = helper.core.base();
        state.hi20_cache.clear();

        for reloc_section in sections {
            for rel in *reloc_section {
                let r_type = rel.r_type().raw();
                if r_type == R_RISCV_PCREL_HI20 || r_type == R_RISCV_GOT_HI20 {
                    let addend = if r_type == R_RISCV_GOT_HI20 {
                        0
                    } else {
                        rel.r_addend(base)
                    };
                    state.hi20_cache.insert(
                        base.wrapping_add(rel.r_offset()),
                        Hi20Relocation {
                            symbol: rel.r_symbol(),
                            addend,
                            r_type,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    pub(crate) fn relocate_object_impl<D, R, PreH, PostH, Obs, H>(
        state: &mut RiscV64ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, PreH, PostH, Obs, H>,
        rel: &ElfRelType<Self>,
        pltgot: &mut PltGotSection,
    ) -> Result<()>
    where
        D: 'static,
        R: RegionAccess,
        H: ElfHashTable<<RiscV64Arch as crate::relocation::RelocationArch>::Layout> + 'static,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
    {
        let r_sym = rel.r_symbol();
        let r_type = rel.r_type().raw();
        let core = helper.core;
        let segments = core.segments();
        let base = core.base();
        let addend = rel.r_addend(base);
        let place = base.wrapping_add(rel.r_offset());
        let unknown_symbol =
            || reloc_error::<Self, _, R, H>(rel, RelocReason::UnknownSymbol, helper.core);
        let value_error = |reason| reloc_error::<Self, _, R, H>(rel, reason, helper.core);

        match r_type {
            R_RISCV_NONE | R_RISCV_RELAX => {}
            R_RISCV_64 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                unsafe {
                    segments.write_object_value(
                        place,
                        RelocValue::new(sym.wrapping_add_signed(addend).get()),
                    )?
                };
            }
            R_RISCV_32 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let value = u32::try_from(sym.wrapping_add_signed(addend).get())
                    .map(RelocValue::new)
                    .map_err(|_| value_error(RelocReason::IntConversionOutOfRange))?;
                unsafe { segments.write_object_value(place, value)? };
            }
            R_RISCV_32_PCREL => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let value = i32::try_from(
                    sym.wrapping_add_signed(addend).get() as i128 - place.get() as i128,
                )
                .map(RelocValue::new)
                .map_err(|_| value_error(RelocReason::IntConversionOutOfRange))?;
                unsafe { segments.write_object_value(place, value)? };
            }
            R_RISCV_BRANCH => {
                let off = branch_offset(helper, addend, place, rel, 4096)?;
                unsafe {
                    segments.update_object_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, off, ImmType::B)
                    })?
                };
            }
            R_RISCV_JAL => {
                let off = branch_offset(helper, addend, place, rel, 1 << 20)?;
                unsafe {
                    segments.update_object_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, off, ImmType::J)
                    })?
                };
            }
            R_RISCV_CALL | R_RISCV_CALL_PLT => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let mut target = sym;
                let direct_off = signed_offset(target, addend, place);
                if r_type == R_RISCV_CALL_PLT
                    && !(direct_off >= -(1i64 << 31) && direct_off < (1i64 << 31))
                {
                    target = Self::ensure_plt_entry(pltgot, r_sym, sym)?;
                }

                let off = signed_offset(target, addend, place);
                if !(off >= -(1i64 << 31) && off < (1i64 << 31)) {
                    return Err(value_error(RelocReason::IntConversionOutOfRange));
                }
                Self::write_auipc_pair(segments, place, off)?;
            }
            R_RISCV_GOT_HI20 => {
                if addend != 0 {
                    return Err(value_error(RelocReason::Unsupported));
                }
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let got_addr = Self::ensure_got_entry(pltgot, r_sym, sym);
                let hi20 = (got_addr.get() as i64 - place.get() as i64 + 0x800) >> 12;
                unsafe {
                    segments.update_object_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, hi20, ImmType::U)
                    })?
                };
            }
            R_RISCV_PCREL_HI20 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let off = signed_offset(sym, addend, place);
                let hi20 = (off + 0x800) >> 12;
                unsafe {
                    segments.update_object_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, hi20, ImmType::U)
                    })?
                };
            }
            R_RISCV_PCREL_LO12_I | R_RISCV_PCREL_LO12_S => {
                let lo12 = Self::resolve_pcrel_lo12(state, helper, rel, pltgot)?;
                let imm_type = if r_type == R_RISCV_PCREL_LO12_I {
                    ImmType::I
                } else {
                    ImmType::S
                };
                unsafe {
                    segments.update_object_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, lo12, imm_type)
                    })?
                };
            }
            R_RISCV_HI20 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let hi20 = (sym.wrapping_add_signed(addend).get() as i64 + 0x800) >> 12;
                unsafe {
                    segments.update_object_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, hi20, ImmType::U)
                    })?
                };
            }
            R_RISCV_LO12_I | R_RISCV_LO12_S => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let lo12 = sym.wrapping_add_signed(addend).get() as i64 & 0xfff;
                let imm_type = if r_type == R_RISCV_LO12_I {
                    ImmType::I
                } else {
                    ImmType::S
                };
                unsafe {
                    segments.update_object_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, lo12, imm_type)
                    })?
                };
            }
            R_RISCV_ADD8 | R_RISCV_ADD16 | R_RISCV_ADD32 | R_RISCV_ADD64 | R_RISCV_SUB8
            | R_RISCV_SUB16 | R_RISCV_SUB32 | R_RISCV_SUB64 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let value = sym.wrapping_add_signed(addend).get();
                let is_add = matches!(
                    r_type,
                    R_RISCV_ADD8 | R_RISCV_ADD16 | R_RISCV_ADD32 | R_RISCV_ADD64
                );
                match r_type {
                    R_RISCV_ADD8 | R_RISCV_SUB8 => {
                        Self::apply_wrapping_arith::<u8, R>(segments, place, value, is_add)?
                    }
                    R_RISCV_ADD16 | R_RISCV_SUB16 => {
                        Self::apply_wrapping_arith::<u16, R>(segments, place, value, is_add)?
                    }
                    R_RISCV_ADD32 | R_RISCV_SUB32 => {
                        Self::apply_wrapping_arith::<u32, R>(segments, place, value, is_add)?
                    }
                    R_RISCV_ADD64 | R_RISCV_SUB64 => {
                        Self::apply_wrapping_arith::<u64, R>(segments, place, value, is_add)?
                    }
                    _ => unreachable!(),
                }
            }
            R_RISCV_SUB6 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let value = sym.wrapping_add_signed(addend).get() as u8;
                unsafe {
                    segments.update_object_value::<u8>(place, |old| {
                        (old & 0xc0) | ((old & 0x3f).wrapping_sub(value) & 0x3f)
                    })?
                };
            }
            R_RISCV_SET6 => {
                let Some(sym) = helper.find_symbol(rel)? else {
                    return Err(unknown_symbol());
                };
                let value = sym.wrapping_add_signed(addend).get() as u8;
                unsafe {
                    segments
                        .update_object_value::<u8>(place, |old| (old & 0xc0) | (value & 0x3f))?
                };
            }
            R_RISCV_SET8 => {
                Self::write_truncated::<u8, D, R, PreH, PostH, Obs, H>(helper, rel, addend, place)?
            }
            R_RISCV_SET16 => {
                Self::write_truncated::<u16, D, R, PreH, PostH, Obs, H>(helper, rel, addend, place)?
            }
            R_RISCV_SET32 => {
                Self::write_truncated::<u32, D, R, PreH, PostH, Obs, H>(helper, rel, addend, place)?
            }
            R_RISCV_RVC_BRANCH => {
                let off = branch_offset(helper, addend, place, rel, 256)?;
                unsafe {
                    segments.update_object_value::<u16>(place, |insn| {
                        Self::encode_imm(insn as u32, off, ImmType::CB) as u16
                    })?
                };
            }
            R_RISCV_RVC_JUMP => {
                let off = branch_offset(helper, addend, place, rel, 2048)?;
                unsafe {
                    segments.update_object_value::<u16>(place, |insn| {
                        Self::encode_imm(insn as u32, off, ImmType::CJ) as u16
                    })?
                };
            }
            _ => return Err(value_error(RelocReason::Unsupported)),
        }

        Ok(())
    }

    pub(crate) fn object_needs_got_impl(rel_type: ElfRelocationType) -> bool {
        matches!(rel_type.raw(), R_RISCV_GOT_HI20 | R_RISCV_CALL_PLT)
    }

    pub(crate) fn object_needs_plt_impl(rel_type: ElfRelocationType) -> bool {
        rel_type.raw() == R_RISCV_CALL_PLT
    }

    #[inline]
    fn ensure_got_entry(pltgot: &mut PltGotSection, r_sym: usize, sym: VmAddr) -> VmAddr {
        match pltgot.add_got_entry(r_sym) {
            GotEntry::Occupied(addr) => addr,
            GotEntry::Vacant(mut got) => {
                got.update(sym);
                got.get_addr()
            }
        }
    }

    fn ensure_plt_entry(pltgot: &mut PltGotSection, r_sym: usize, sym: VmAddr) -> Result<VmAddr> {
        match pltgot.add_plt_entry(r_sym) {
            PltEntry::Occupied(addr) => Ok(addr),
            PltEntry::Vacant { plt, mut got } => {
                let plt_entry_addr = VmAddr::from_ptr(plt.as_ptr());
                got.update(sym);
                let got_off = got.get_addr().get() as i64 - plt_entry_addr.get() as i64;
                let got_hi20 = (got_off + 0x800) >> 12;
                let got_lo12 = got_off & 0xfff;
                let ptr = plt.as_mut_ptr().cast::<u32>();
                unsafe {
                    let auipc = ptr.read_unaligned();
                    ptr.write_unaligned(Self::encode_imm(auipc, got_hi20, ImmType::U));
                    let ld = ptr.add(1).read_unaligned();
                    ptr.add(1)
                        .write_unaligned(Self::encode_imm(ld, got_lo12, ImmType::I));
                }
                Ok(plt_entry_addr)
            }
        }
    }

    fn resolve_pcrel_lo12<D, R, PreH, PostH, Obs, H>(
        state: &RiscV64ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, PreH, PostH, Obs, H>,
        rel: &ElfRelType<Self>,
        pltgot: &mut PltGotSection,
    ) -> Result<i64>
    where
        D: 'static,
        R: RegionAccess,
        H: ElfHashTable<<RiscV64Arch as crate::relocation::RelocationArch>::Layout> + 'static,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
    {
        let Some(auipc_addr) = helper.find_symbol(rel)? else {
            return Err(reloc_error::<Self, _, R, H>(
                rel,
                RelocReason::UnknownSymbol,
                helper.core,
            ));
        };
        let Some(hi20) = state.hi20_cache.get(&auipc_addr).copied() else {
            return Err(reloc_error::<Self, _, R, H>(
                rel,
                RelocReason::Unsupported,
                helper.core,
            ));
        };

        let off = if hi20.r_type == R_RISCV_GOT_HI20 {
            let Some(sym) = helper.find_symdef(hi20.symbol).map(|sym| sym.convert()) else {
                return Err(reloc_error::<Self, _, R, H>(
                    rel,
                    RelocReason::UnknownSymbol,
                    helper.core,
                ));
            };
            let got_addr = Self::ensure_got_entry(pltgot, hi20.symbol, sym);
            got_addr.get() as i64 - auipc_addr.get() as i64
        } else {
            let Some(sym) = helper.find_symdef(hi20.symbol).map(|sym| sym.convert()) else {
                return Err(reloc_error::<Self, _, R, H>(
                    rel,
                    RelocReason::UnknownSymbol,
                    helper.core,
                ));
            };
            let target = sym
                .wrapping_add_signed(hi20.addend)
                .wrapping_add_signed(rel.r_addend(helper.core.base()));
            target.get() as i64 - auipc_addr.get() as i64
        };

        let hi20 = (off + 0x800) >> 12;
        Ok(off - (hi20 << 12))
    }

    fn write_auipc_pair<R: RegionAccess>(
        segments: &ElfSegments<R>,
        place: VmAddr,
        off: i64,
    ) -> Result<()> {
        let hi20 = (off + 0x800) >> 12;
        let lo12 = off & 0xfff;
        unsafe {
            segments.update_object_value::<u32>(place, |insn| {
                Self::encode_imm(insn, hi20, ImmType::U)
            })?;
            segments.update_object_value::<u32>(place.wrapping_add(VmOffset::new(4)), |insn| {
                Self::encode_imm(insn, lo12, ImmType::I)
            })?;
        }
        Ok(())
    }

    fn apply_wrapping_arith<T, R>(
        segments: &ElfSegments<R>,
        place: VmAddr,
        value: usize,
        is_add: bool,
    ) -> Result<()>
    where
        T: WrappingRelocWord + crate::ByteRepr,
        R: RegionAccess,
    {
        unsafe {
            segments.update_object_value::<T>(place, |old| {
                let rhs = T::trunc_from_usize(value);
                if is_add {
                    old.wrapping_add(rhs)
                } else {
                    old.wrapping_sub(rhs)
                }
            })?
        };
        Ok(())
    }

    fn write_truncated<T, D, R, PreH, PostH, Obs, H>(
        helper: &mut RelocHelper<'_, D, Self, R, PreH, PostH, Obs, H>,
        rel: &ElfRelType<Self>,
        addend: isize,
        place: VmAddr,
    ) -> Result<()>
    where
        T: WrappingRelocWord + crate::ByteRepr,
        D: 'static,
        R: RegionAccess,
        H: ElfHashTable<<RiscV64Arch as crate::relocation::RelocationArch>::Layout> + 'static,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
    {
        let Some(sym) = helper.find_symbol(rel)? else {
            return Err(reloc_error::<Self, _, R, H>(
                rel,
                RelocReason::UnknownSymbol,
                helper.core,
            ));
        };
        unsafe {
            helper.core.segments().write_object_value(
                place,
                RelocValue::new(T::trunc_from_usize(sym.wrapping_add_signed(addend).get())),
            )?
        };
        Ok(())
    }

    #[inline]
    fn encode_imm(insn: u32, val: i64, ty: ImmType) -> u32 {
        match ty {
            ImmType::U => (insn & 0xfff) | ((val as u32) << 12),
            ImmType::I => (insn & 0xfffff) | (((val & 0xfff) as u32) << 20),
            ImmType::S => {
                let imm11_5 = ((val >> 5) & 0x7f) as u32;
                let imm4_0 = (val & 0x1f) as u32;
                (insn & 0x1fff07f) | (imm11_5 << 25) | (imm4_0 << 7)
            }
            ImmType::B => {
                let imm12 = ((val >> 12) & 0x1) as u32;
                let imm10_5 = ((val >> 5) & 0x3f) as u32;
                let imm4_1 = ((val >> 1) & 0xf) as u32;
                let imm11 = ((val >> 11) & 0x1) as u32;
                (insn & 0x1fff07f) | (imm12 << 31) | (imm10_5 << 25) | (imm4_1 << 8) | (imm11 << 7)
            }
            ImmType::J => {
                let imm20 = ((val >> 20) & 0x1) as u32;
                let imm10_1 = ((val >> 1) & 0x3ff) as u32;
                let imm11 = ((val >> 11) & 0x1) as u32;
                let imm19_12 = ((val >> 12) & 0xff) as u32;
                (insn & 0xfff) | (imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12)
            }
            ImmType::CB => {
                let imm8 = ((val >> 8) & 0x1) as u16;
                let imm4_3 = ((val >> 3) & 0x3) as u16;
                let imm7_6 = ((val >> 6) & 0x3) as u16;
                let imm2_1 = ((val >> 1) & 0x3) as u16;
                let imm5 = ((val >> 5) & 0x1) as u16;
                (((insn as u16) & 0xe383)
                    | (imm8 << 12)
                    | (imm4_3 << 10)
                    | (imm7_6 << 5)
                    | (imm2_1 << 3)
                    | (imm5 << 2)) as u32
            }
            ImmType::CJ => {
                let imm11 = ((val >> 11) & 0x1) as u16;
                let imm4 = ((val >> 4) & 0x1) as u16;
                let imm9_8 = ((val >> 8) & 0x3) as u16;
                let imm10 = ((val >> 10) & 0x1) as u16;
                let imm6 = ((val >> 6) & 0x1) as u16;
                let imm7 = ((val >> 7) & 0x1) as u16;
                let imm3_1 = ((val >> 1) & 0x7) as u16;
                let imm5 = ((val >> 5) & 0x1) as u16;
                (((insn as u16) & 0xe003)
                    | (imm11 << 12)
                    | (imm4 << 11)
                    | (imm9_8 << 9)
                    | (imm10 << 8)
                    | (imm6 << 7)
                    | (imm7 << 6)
                    | (imm3_1 << 3)
                    | (imm5 << 2)) as u32
            }
        }
    }
}

fn signed_offset(target: VmAddr, addend: isize, place: VmAddr) -> i64 {
    (target.get() as i128 + addend as i128 - place.get() as i128) as i64
}

fn branch_offset<D, R, PreH, PostH, Obs, H>(
    helper: &mut RelocHelper<'_, D, RiscV64Arch, R, PreH, PostH, Obs, H>,
    addend: isize,
    place: VmAddr,
    rel: &ElfRelType<RiscV64Arch>,
    range: i64,
) -> Result<i64>
where
    D: 'static,
    R: RegionAccess,
    H: ElfHashTable<<RiscV64Arch as crate::relocation::RelocationArch>::Layout> + 'static,
    PreH: RelocationHandler<RiscV64Arch> + ?Sized,
    PostH: RelocationHandler<RiscV64Arch> + ?Sized,
    Obs: RelocationObserver<RiscV64Arch> + ?Sized,
{
    let Some(sym) = helper.find_symbol(rel)? else {
        return Err(reloc_error::<RiscV64Arch, _, R, H>(
            rel,
            RelocReason::UnknownSymbol,
            helper.core,
        ));
    };
    let off = signed_offset(sym, addend, place);
    if off & 1 != 0 || off < -range || off >= range {
        return Err(reloc_error::<RiscV64Arch, _, R, H>(
            rel,
            RelocReason::IntConversionOutOfRange,
            helper.core,
        ));
    }
    Ok(off)
}
