use crate::{
    RelocReason, Result,
    arch::riscv64::relocation::RiscV64Arch,
    elf::{ElfRelEntry, ElfRelType, ElfRelocationType, ElfShdr},
    memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
    object::{
        layout::{GotEntry, ObjectRelocKey, PltEntry, PltGotSection},
        object_relocation_sections, section_entries,
    },
    observer::RelocationObserver,
    relocation::{ObjectRelocationArch, RelocHelper, RelocationHandler, reloc_error},
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
    got_key: Option<ObjectRelocKey>,
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
    fn prepare_object_relocation<D, R, Tls, PreH, PostH, Obs, H, Memory>(
        state: &mut Self::ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, Tls, PreH, PostH, Obs, H, Memory>,
        shdrs: &[ElfShdr<<Self as crate::relocation::RelocationArch>::Layout>],
    ) -> Result<()>
    where
        D: 'static,
        R: RegionAccess,
        Tls: crate::tls::TlsResolver<Self>,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        Self::prepare_object_relocation_impl(state, helper, shdrs)
    }

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn relocate_object<D, R, Tls, PreH, PostH, Obs, H, Memory>(
        state: &mut Self::ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, Tls, PreH, PostH, Obs, H, Memory>,
        rel: &ElfRelType<Self>,
        target: &ElfShdr<<Self as crate::relocation::RelocationArch>::Layout>,
        pltgot: &mut PltGotSection,
    ) -> Result<()>
    where
        D: 'static,
        R: RegionAccess,
        Tls: crate::tls::TlsResolver<Self>,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        Self::relocate_object_impl(state, helper, rel, target, pltgot)
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
    pub(crate) fn prepare_object_relocation_impl<D, R, Tls, PreH, PostH, Obs, H, Memory>(
        state: &mut RiscV64ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, Tls, PreH, PostH, Obs, H, Memory>,
        shdrs: &[ElfShdr<<Self as crate::relocation::RelocationArch>::Layout>],
    ) -> Result<()>
    where
        D: 'static,
        R: RegionAccess,
        Tls: crate::tls::TlsResolver<Self>,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        state.hi20_cache.clear();

        for (_, _, target, relocation_shdr) in object_relocation_sections::<Self>(shdrs) {
            let rels = section_entries::<
                <Self as crate::relocation::RelocationArch>::Layout,
                ElfRelType<Self>,
                _,
            >(helper.memory(), relocation_shdr)?;
            for rel in rels {
                let r_type = rel.r_type().raw();
                if r_type == R_RISCV_PCREL_HI20 || r_type == R_RISCV_GOT_HI20 {
                    let place = VmAddr::new(target.sh_addr()) + rel.r_offset();
                    let addend = if r_type == R_RISCV_GOT_HI20 {
                        0
                    } else {
                        rel.read_addend(helper.memory(), place)?
                    };
                    state.hi20_cache.insert(
                        place,
                        Hi20Relocation {
                            symbol: rel.r_symbol(),
                            addend,
                            r_type,
                            got_key: (r_type == R_RISCV_GOT_HI20)
                                .then(|| ObjectRelocKey::new::<Self>(rel, addend)),
                        },
                    );
                }
            }
        }

        Ok(())
    }

    pub(crate) fn relocate_object_impl<D, R, Tls, PreH, PostH, Obs, H, Memory>(
        state: &mut RiscV64ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, Tls, PreH, PostH, Obs, H, Memory>,
        rel: &ElfRelType<Self>,
        target: &ElfShdr<<Self as crate::relocation::RelocationArch>::Layout>,
        pltgot: &mut PltGotSection,
    ) -> Result<()>
    where
        D: 'static,
        R: RegionAccess,
        Tls: crate::tls::TlsResolver<Self>,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        let r_type = rel.r_type().raw();
        let place = VmAddr::new(target.sh_addr()) + rel.r_offset();
        let addend = rel.read_addend(helper.memory(), place)?;
        let value_error =
            |reason| reloc_error::<Self, _, R, Tls, H>(rel, reason, helper.core, helper.symbols());

        match r_type {
            R_RISCV_NONE | R_RISCV_RELAX => {}
            R_RISCV_64 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                unsafe {
                    helper
                        .memory()
                        .write_value(place, sym.wrapping_add_signed(addend).get())?
                };
            }
            R_RISCV_32 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value = u32::try_from(sym.wrapping_add_signed(addend).get())
                    .map_err(|_| value_error(RelocReason::IntConversionOutOfRange))?;
                unsafe { helper.memory().write_value(place, value)? };
            }
            R_RISCV_32_PCREL => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value = i32::try_from(
                    sym.wrapping_add_signed(addend).get() as i128 - place.get() as i128,
                )
                .map_err(|_| value_error(RelocReason::IntConversionOutOfRange))?;
                unsafe { helper.memory().write_value(place, value)? };
            }
            R_RISCV_BRANCH => {
                let off = branch_offset(helper, addend, place, rel, 4096)?;
                unsafe {
                    helper.memory().update_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, off, ImmType::B)
                    })?
                };
            }
            R_RISCV_JAL => {
                let off = branch_offset(helper, addend, place, rel, 1 << 20)?;
                unsafe {
                    helper.memory().update_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, off, ImmType::J)
                    })?
                };
            }
            R_RISCV_CALL | R_RISCV_CALL_PLT => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let mut target = sym;
                let direct_off = signed_offset(target, addend, place);
                if r_type == R_RISCV_CALL_PLT
                    && !(-(1i64 << 31)..(1i64 << 31)).contains(&direct_off)
                {
                    let key = ObjectRelocKey::new::<Self>(rel, addend);
                    target = Self::ensure_plt_entry(pltgot, key, sym);
                }

                let off = signed_offset(target, addend, place);
                if !(-(1i64 << 31)..(1i64 << 31)).contains(&off) {
                    return Err(value_error(RelocReason::IntConversionOutOfRange));
                }
                Self::write_auipc_pair(helper.memory(), place, off)?;
            }
            R_RISCV_GOT_HI20 => {
                if addend != 0 {
                    return Err(value_error(RelocReason::Unsupported));
                }
                let sym = helper.symbol_addr(rel.r_symbol());
                let key = ObjectRelocKey::new::<Self>(rel, addend);
                let got_addr = Self::ensure_got_entry(pltgot, key, sym);
                let hi20 = (got_addr.get() as i64 - place.get() as i64 + 0x800) >> 12;
                unsafe {
                    helper.memory().update_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, hi20, ImmType::U)
                    })?
                };
            }
            R_RISCV_PCREL_HI20 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let off = signed_offset(sym, addend, place);
                let hi20 = (off + 0x800) >> 12;
                unsafe {
                    helper.memory().update_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, hi20, ImmType::U)
                    })?
                };
            }
            R_RISCV_PCREL_LO12_I | R_RISCV_PCREL_LO12_S => {
                let lo12 = Self::resolve_pcrel_lo12(state, helper, rel, target, pltgot)?;
                let imm_type = if r_type == R_RISCV_PCREL_LO12_I {
                    ImmType::I
                } else {
                    ImmType::S
                };
                unsafe {
                    helper
                        .memory()
                        .update_value::<u32>(place, |insn| Self::encode_imm(insn, lo12, imm_type))?
                };
            }
            R_RISCV_HI20 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let hi20 = (sym.wrapping_add_signed(addend).get() as i64 + 0x800) >> 12;
                unsafe {
                    helper.memory().update_value::<u32>(place, |insn| {
                        Self::encode_imm(insn, hi20, ImmType::U)
                    })?
                };
            }
            R_RISCV_LO12_I | R_RISCV_LO12_S => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let lo12 = sym.wrapping_add_signed(addend).get() as i64 & 0xfff;
                let imm_type = if r_type == R_RISCV_LO12_I {
                    ImmType::I
                } else {
                    ImmType::S
                };
                unsafe {
                    helper
                        .memory()
                        .update_value::<u32>(place, |insn| Self::encode_imm(insn, lo12, imm_type))?
                };
            }
            R_RISCV_ADD8 | R_RISCV_ADD16 | R_RISCV_ADD32 | R_RISCV_ADD64 | R_RISCV_SUB8
            | R_RISCV_SUB16 | R_RISCV_SUB32 | R_RISCV_SUB64 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value = sym.wrapping_add_signed(addend).get();
                let is_add = matches!(
                    r_type,
                    R_RISCV_ADD8 | R_RISCV_ADD16 | R_RISCV_ADD32 | R_RISCV_ADD64
                );
                match r_type {
                    R_RISCV_ADD8 | R_RISCV_SUB8 => Self::apply_wrapping_arith::<u8, Memory>(
                        helper.memory(),
                        place,
                        value,
                        is_add,
                    )?,
                    R_RISCV_ADD16 | R_RISCV_SUB16 => Self::apply_wrapping_arith::<u16, Memory>(
                        helper.memory(),
                        place,
                        value,
                        is_add,
                    )?,
                    R_RISCV_ADD32 | R_RISCV_SUB32 => Self::apply_wrapping_arith::<u32, Memory>(
                        helper.memory(),
                        place,
                        value,
                        is_add,
                    )?,
                    R_RISCV_ADD64 | R_RISCV_SUB64 => Self::apply_wrapping_arith::<u64, Memory>(
                        helper.memory(),
                        place,
                        value,
                        is_add,
                    )?,
                    _ => unreachable!(),
                }
            }
            R_RISCV_SUB6 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value = sym.wrapping_add_signed(addend).get() as u8;
                unsafe {
                    helper.memory().update_value::<u8>(place, |old| {
                        (old & 0xc0) | ((old & 0x3f).wrapping_sub(value) & 0x3f)
                    })?
                };
            }
            R_RISCV_SET6 => {
                let sym = helper.symbol_addr(rel.r_symbol());
                let value = sym.wrapping_add_signed(addend).get() as u8;
                unsafe {
                    helper
                        .memory()
                        .update_value::<u8>(place, |old| (old & 0xc0) | (value & 0x3f))?
                };
            }
            R_RISCV_SET8 => Self::write_truncated::<u8, D, R, Tls, PreH, PostH, Obs, H, Memory>(
                helper, rel, addend, place,
            )?,
            R_RISCV_SET16 => Self::write_truncated::<u16, D, R, Tls, PreH, PostH, Obs, H, Memory>(
                helper, rel, addend, place,
            )?,
            R_RISCV_SET32 => Self::write_truncated::<u32, D, R, Tls, PreH, PostH, Obs, H, Memory>(
                helper, rel, addend, place,
            )?,
            R_RISCV_RVC_BRANCH => {
                let off = branch_offset(helper, addend, place, rel, 256)?;
                unsafe {
                    helper.memory().update_value::<u16>(place, |insn| {
                        Self::encode_imm(u32::from(insn), off, ImmType::CB) as u16
                    })?
                };
            }
            R_RISCV_RVC_JUMP => {
                let off = branch_offset(helper, addend, place, rel, 2048)?;
                unsafe {
                    helper.memory().update_value::<u16>(place, |insn| {
                        Self::encode_imm(u32::from(insn), off, ImmType::CJ) as u16
                    })?
                };
            }
            _ => return Err(value_error(RelocReason::Unsupported)),
        }

        Ok(())
    }

    pub(crate) fn object_needs_got_impl(r_type: ElfRelocationType) -> bool {
        r_type.raw() == R_RISCV_GOT_HI20
    }

    pub(crate) fn object_needs_plt_impl(r_type: ElfRelocationType) -> bool {
        r_type.raw() == R_RISCV_CALL_PLT
    }

    #[inline]
    fn ensure_got_entry(pltgot: &mut PltGotSection, key: ObjectRelocKey, sym: VmAddr) -> VmAddr {
        match pltgot.add_got_entry(key) {
            GotEntry::Occupied(addr) => addr,
            GotEntry::Vacant(mut got) => {
                got.update(sym);
                got.get_addr()
            }
        }
    }

    fn ensure_plt_entry(pltgot: &mut PltGotSection, key: ObjectRelocKey, sym: VmAddr) -> VmAddr {
        match pltgot.add_plt_entry(key) {
            PltEntry::Occupied(addr) => addr,
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
                plt_entry_addr
            }
        }
    }

    fn resolve_pcrel_lo12<D, R, Tls, PreH, PostH, Obs, H, Memory>(
        state: &RiscV64ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, Tls, PreH, PostH, Obs, H, Memory>,
        rel: &ElfRelType<Self>,
        target: &ElfShdr<<Self as crate::relocation::RelocationArch>::Layout>,
        pltgot: &mut PltGotSection,
    ) -> Result<i64>
    where
        D: 'static,
        R: RegionAccess,
        Tls: crate::tls::TlsResolver<Self>,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        let auipc_addr = helper.symbol_addr(rel.r_symbol());
        let Some(hi20) = state.hi20_cache.get(&auipc_addr).copied() else {
            return Err(reloc_error::<Self, _, R, Tls, H>(
                rel,
                RelocReason::Unsupported,
                helper.core,
                helper.symbols(),
            ));
        };

        let off = if hi20.r_type == R_RISCV_GOT_HI20 {
            let sym = helper.symbol_addr(hi20.symbol);
            let key = hi20
                .got_key
                .expect("R_RISCV_GOT_HI20 relocation must carry a GOT key");
            let got_addr = Self::ensure_got_entry(pltgot, key, sym);
            got_addr.get() as i64 - auipc_addr.get() as i64
        } else {
            let sym = helper.symbol_addr(hi20.symbol);
            let place = VmAddr::new(target.sh_addr()) + rel.r_offset();
            let target = sym
                .wrapping_add_signed(hi20.addend)
                .wrapping_add_signed(rel.read_addend(helper.memory(), place)?);
            target.get() as i64 - auipc_addr.get() as i64
        };

        let hi20 = (off + 0x800) >> 12;
        Ok(off - (hi20 << 12))
    }

    fn write_auipc_pair<Memory>(segments: &Memory, place: VmAddr, off: i64) -> Result<()>
    where
        Memory: ImageMemory,
    {
        let hi20 = (off + 0x800) >> 12;
        let lo12 = off & 0xfff;
        unsafe {
            segments.update_value::<u32>(place, |insn| Self::encode_imm(insn, hi20, ImmType::U))?;
            segments.update_value::<u32>(place.wrapping_add(VmOffset::new(4)), |insn| {
                Self::encode_imm(insn, lo12, ImmType::I)
            })?;
        }
        Ok(())
    }

    fn apply_wrapping_arith<T, Memory>(
        segments: &Memory,
        place: VmAddr,
        value: usize,
        is_add: bool,
    ) -> Result<()>
    where
        T: WrappingRelocWord + crate::ByteRepr,
        Memory: ImageMemory,
    {
        unsafe {
            segments.update_value::<T>(place, |old| {
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

    fn write_truncated<T, D, R, Tls, PreH, PostH, Obs, H, Memory>(
        helper: &mut RelocHelper<'_, D, Self, R, Tls, PreH, PostH, Obs, H, Memory>,
        rel: &ElfRelType<Self>,
        addend: isize,
        place: VmAddr,
    ) -> Result<()>
    where
        T: WrappingRelocWord + crate::ByteRepr,
        D: 'static,
        R: RegionAccess,
        Tls: crate::tls::TlsResolver<Self>,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        let sym = helper.symbol_addr(rel.r_symbol());
        unsafe {
            helper.memory().write_value(
                place,
                T::trunc_from_usize(sym.wrapping_add_signed(addend).get()),
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
                u32::from(
                    ((insn as u16) & 0xe383)
                        | (imm8 << 12)
                        | (imm4_3 << 10)
                        | (imm7_6 << 5)
                        | (imm2_1 << 3)
                        | (imm5 << 2),
                )
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
                u32::from(
                    ((insn as u16) & 0xe003)
                        | (imm11 << 12)
                        | (imm4 << 11)
                        | (imm9_8 << 9)
                        | (imm10 << 8)
                        | (imm6 << 7)
                        | (imm7 << 6)
                        | (imm3_1 << 3)
                        | (imm5 << 2),
                )
            }
        }
    }
}

fn signed_offset(target: VmAddr, addend: isize, place: VmAddr) -> i64 {
    (target.get() as i128 + addend as i128 - place.get() as i128) as i64
}

fn branch_offset<D, R, Tls, PreH, PostH, Obs, H, Memory>(
    helper: &mut RelocHelper<'_, D, RiscV64Arch, R, Tls, PreH, PostH, Obs, H, Memory>,
    addend: isize,
    place: VmAddr,
    rel: &ElfRelType<RiscV64Arch>,
    range: i64,
) -> Result<i64>
where
    D: 'static,
    R: RegionAccess,
    Tls: crate::tls::TlsResolver<RiscV64Arch>,
    PreH: RelocationHandler<RiscV64Arch> + ?Sized,
    PostH: RelocationHandler<RiscV64Arch> + ?Sized,
    Obs: RelocationObserver<RiscV64Arch> + ?Sized,
    Memory: ImageMemory,
{
    let sym = helper.symbol_addr(rel.r_symbol());
    let off = signed_offset(sym, addend, place);
    if off & 1 != 0 || off < -range || off >= range {
        return Err(reloc_error::<RiscV64Arch, _, R, Tls, H>(
            rel,
            RelocReason::IntConversionOutOfRange,
            helper.core,
            helper.symbols(),
        ));
    }
    Ok(off)
}
