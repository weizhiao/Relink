use super::{
    defs::{LazyBindingEntries, LazyRuntime},
    traits::LazyBinder,
};
use crate::{
    Error, LazyBindingError, RelocationError, Result, arch::NativeArch, memory::VmAddr,
    relocation::RelocationArch,
};

#[cold]
#[inline(never)]
fn unresolved_symbol(rela_idx: usize) -> ! {
    panic!("lazy binding failed: unresolved symbol for PLT relocation {rela_idx}");
}

#[cold]
#[inline(never)]
fn resolve_error(error: Error) -> ! {
    panic!("{error}");
}

unsafe fn resolve<Arch>(runtime: VmAddr, rela_idx: usize) -> usize
where
    Arch: RelocationArch,
    <Arch::Layout as crate::elf::ElfLayout>::Word: crate::ByteRepr,
{
    let runtime = unsafe { LazyRuntime::<Arch>::from_runtime(runtime) };
    match runtime.resolve_default(rela_idx) {
        Ok(Some(symbol)) => symbol.get(),
        Ok(None) => unresolved_symbol(rela_idx),
        Err(error) => resolve_error(error),
    }
}

/// Native same-process lazy PLT binder.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeLazyBinder;

impl NativeLazyBinder {
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl<Arch> LazyBinder<Arch> for NativeLazyBinder
where
    Arch: RelocationArch,
{
    #[inline]
    fn prepare_entries(&self, runtime: LazyRuntime<Arch>) -> Result<LazyBindingEntries> {
        if !Arch::SUPPORTS_NATIVE_RUNTIME {
            return Err(RelocationError::LazyBinding(LazyBindingError::NativeUnsupported).into());
        }

        Ok(LazyBindingEntries::new(
            runtime.runtime(),
            VmAddr::from_ptr(crate::arch::dl_runtime_resolve as *const ()),
        ))
    }
}

pub(crate) unsafe extern "C" fn dl_fixup(runtime: usize, rela_idx: usize) -> usize {
    unsafe { resolve::<NativeArch>(VmAddr::new(runtime), rela_idx) }
}
