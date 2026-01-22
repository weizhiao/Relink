//! architectures supported by the ELF loader.
cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")]{
        pub(crate) type  StaticRelocator = X86_64Relocator;
    }else {
        pub(crate) type  StaticRelocator = DummyRelocator;
        pub(crate) struct DummyRelocator;
        pub(crate) const PLT_ENTRY_SIZE: usize = 16;

        pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0xff, 0x25, 0, 0, 0, 0, // jmp *GOTPLT+idx(%rip)
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // (padding)
        ];

        impl crate::relocation::StaticReloc for DummyRelocator {
            fn relocate<D, PreS, PostS, PreH, PostH>(
                _helper: &mut crate::relocation::RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
                _rel: &crate::elf::ElfRelType,
                _pltgot: &mut crate::segment::section::PltGotSection,
            ) -> crate::Result<()>
            where
                PreS: crate::relocation::SymbolLookup + ?Sized,
                PostS: crate::relocation::SymbolLookup + ?Sized,
                PreH: crate::relocation::RelocationHandler + ?Sized,
                PostH: crate::relocation::RelocationHandler + ?Sized,
            {
                Ok(())
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")]{
        mod x86_64;
        pub use x86_64::*;
    }else if #[cfg(target_arch = "riscv64")]{
        mod riscv64;
        pub use riscv64::*;
    }else if #[cfg(target_arch = "riscv32")]{
        mod riscv32;
        pub use riscv32::*;
    }else if #[cfg(target_arch="aarch64")]{
        mod aarch64;
        pub use aarch64::*;
    }else if #[cfg(target_arch="loongarch64")]{
        mod loongarch64;
        pub use loongarch64::*;
    }else if #[cfg(target_arch = "x86")]{
        mod x86;
        pub use x86::*;
    }else if #[cfg(target_arch = "arm")]{
        mod arm;
        pub use arm::*;
    }
}

pub const REL_NONE: u32 = 0;

#[inline]
pub(crate) fn prepare_lazy_bind(got: *mut usize, dylib: usize) {
    // 这是安全的，延迟绑定时库是存在的
    unsafe {
        got.add(DYLIB_OFFSET).write(dylib);
        got.add(RESOLVE_FUNCTION_OFFSET)
            .write(dl_runtime_resolve as usize);
    }
}
