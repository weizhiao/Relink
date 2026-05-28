#[cfg(all(feature = "object", target_arch = "x86_64"))]
pub(crate) use super::x86_64::object::{PLT_ENTRY, PLT_ENTRY_SIZE};

#[cfg(all(feature = "object", target_arch = "riscv64"))]
pub(crate) use super::riscv64::object::{PLT_ENTRY, PLT_ENTRY_SIZE};

#[cfg(all(
    feature = "object",
    not(any(target_arch = "x86_64", target_arch = "riscv64"))
))]
pub(crate) const PLT_ENTRY_SIZE: usize = 16;

#[cfg(all(
    feature = "object",
    not(any(target_arch = "x86_64", target_arch = "riscv64"))
))]
pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
    0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25, 0, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

#[cfg(feature = "object")]
use crate::elf::{ElfRelType, ElfRelocationType};
#[cfg(feature = "object")]
use crate::observer::RelocationObserver;
#[cfg(feature = "object")]
use crate::relocation::{RelocHelper, RelocationArch, RelocationHandler, reloc_error};
#[cfg(feature = "object")]
use crate::{RelocReason, Result, os::HostRegion};

/// Object-file (`ET_REL`) relocation support layered on top of [`RelocationArch`].
#[cfg(feature = "object")]
#[doc(hidden)]
pub trait ObjectRelocationArch: RelocationArch {
    type ObjectRelocationState: Default;

    /// Whether relocatable-object relocation sites may be less aligned than the
    /// typed value being patched.
    const OBJECT_RELOCATION_ALLOWS_UNALIGNED_ACCESS: bool = false;

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn prepare_object_relocation<D, PreH, PostH, Obs>(
        _state: &mut Self::ObjectRelocationState,
        _helper: &mut RelocHelper<'_, D, Self, HostRegion, PreH, PostH, Obs>,
        _sections: &[&'static [ElfRelType<Self>]],
    ) -> Result<()>
    where
        Self: Sized,
        D: 'static,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
    {
        Ok(())
    }

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn relocate_object<D, PreH, PostH, Obs>(
        _state: &mut Self::ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, HostRegion, PreH, PostH, Obs>,
        rel: &ElfRelType<Self>,
        _pltgot: &mut crate::object::layout::PltGotSection,
    ) -> Result<()>
    where
        Self: Sized,
        D: 'static,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
    {
        Err(reloc_error::<Self, _, HostRegion>(
            rel,
            RelocReason::Unsupported,
            helper.core,
        ))
    }

    #[inline]
    fn object_needs_got(_r_type: ElfRelocationType) -> bool
    where
        Self: Sized,
    {
        false
    }

    #[inline]
    fn object_needs_plt(_r_type: ElfRelocationType) -> bool
    where
        Self: Sized,
    {
        false
    }
}
