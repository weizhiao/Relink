#[cfg(target_arch = "x86_64")]
pub(crate) use super::x86_64::object::{ObjectRelocator, PLT_ENTRY, PLT_ENTRY_SIZE};

#[cfg(not(target_arch = "x86_64"))]
pub(crate) struct DummyObjectRelocator;

#[cfg(not(target_arch = "x86_64"))]
pub(crate) type ObjectRelocator = DummyObjectRelocator;

#[cfg(not(target_arch = "x86_64"))]
pub(crate) const PLT_ENTRY_SIZE: usize = 16;

#[cfg(not(target_arch = "x86_64"))]
pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
    0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25, 0, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

#[cfg(not(target_arch = "x86_64"))]
impl crate::object::ObjectReloc for DummyObjectRelocator {
    fn relocate<D, PreS, PostS, PreH, PostH>(
        _helper: &mut crate::relocation::RelocHelper<
            '_,
            D,
            crate::arch::NativeArch,
            PreS,
            PostS,
            PreH,
            PostH,
        >,
        _rel: &crate::elf::ElfRelType<crate::arch::NativeArch>,
        _pltgot: &mut crate::object::layout::PltGotSection,
    ) -> crate::Result<()>
    where
        PreS: crate::relocation::SymbolLookup + ?Sized,
        PostS: crate::relocation::SymbolLookup + ?Sized,
        PreH: crate::relocation::RelocationHandler<crate::arch::NativeArch> + ?Sized,
        PostH: crate::relocation::RelocationHandler<crate::arch::NativeArch> + ?Sized,
    {
        Ok(())
    }
}
