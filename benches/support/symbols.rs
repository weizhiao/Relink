//! Resolve the same workload ABI through either loader.
use elf_loader::image::Module as ElfModule;
use libloading::os::unix::Library;
use std::ffi::CStr;

pub trait Symbols {
    /// # Safety
    /// `T` must match the named symbol's C ABI type.
    unsafe fn symbol<T: Copy>(&self, name: &CStr) -> T;
}

impl Symbols for dyn ElfModule {
    unsafe fn symbol<T: Copy>(&self, name: &CStr) -> T {
        *unsafe { self.get::<T>(name.to_bytes()) }.unwrap().unwrap()
    }
}

impl Symbols for Library {
    unsafe fn symbol<T: Copy>(&self, name: &CStr) -> T {
        *unsafe { self.get::<T>(name.to_bytes_with_nul()) }.unwrap()
    }
}
