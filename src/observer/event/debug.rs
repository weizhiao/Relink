use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfDyn, ElfDynamicTag},
    os::{HostRegion, RegionAccess, VmAddr},
    relocation::{RelocValue, RelocationArch},
    segment::ElfSegments,
};
use core::marker::PhantomData;

/// A mutable `DT_DEBUG` dynamic entry discovered in an image.
///
/// The observer decides whether and how to patch it. This keeps debugger-facing
/// state such as `r_debug` and `link_map` owned by the embedding runtime.
pub struct DtDebugEntry<'a, Arch: RelocationArch = NativeArch, R: RegionAccess = HostRegion> {
    addr: VmAddr,
    segments: &'a ElfSegments<R>,
    _marker: PhantomData<fn() -> Arch>,
}

impl<'a, Arch: RelocationArch, R: RegionAccess> DtDebugEntry<'a, Arch, R> {
    #[inline]
    pub(crate) const fn new(addr: VmAddr, segments: &'a ElfSegments<R>) -> Self {
        Self {
            addr,
            segments,
            _marker: PhantomData,
        }
    }

    /// Returns the runtime address of the `DT_DEBUG` dynamic entry.
    #[inline]
    pub const fn addr(&self) -> VmAddr {
        self.addr
    }

    /// Writes the runtime address of an externally owned `r_debug` object.
    #[inline]
    pub fn write_r_debug_addr(&self, addr: VmAddr) -> Result<()> {
        let entry = ElfDyn::<Arch::Layout>::new(ElfDynamicTag::DEBUG, addr.get());
        unsafe { self.segments.write_value(self.addr, RelocValue::new(entry)) }
    }
}
