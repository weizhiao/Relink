use crate::os::VmAddr;
use alloc::boxed::Box;

pub(crate) type LifecycleArray = Box<[VmAddr]>;

/// ELF lifecycle functions associated with `.init`, `.init_array`, `.fini`, or `.fini_array`.
///
/// The loader stores target addresses here rather than host function pointers.
/// Native handlers may convert those addresses into callable function pointers;
/// emulators can execute the same addresses in the guest environment.
pub struct Lifecycle {
    func: Option<VmAddr>,
    func_array: Option<LifecycleArray>,
}

impl Lifecycle {
    #[inline]
    pub(crate) fn new(func: Option<VmAddr>, func_array: Option<LifecycleArray>) -> Self {
        Self { func, func_array }
    }

    #[inline]
    pub(crate) fn empty() -> Self {
        Self::new(None, None)
    }

    pub(crate) fn array_from_vm_addrs(addrs: impl IntoIterator<Item = VmAddr>) -> LifecycleArray {
        addrs.into_iter().collect()
    }

    /// VM address of the single lifecycle function, if present.
    ///
    /// The returned address is not necessarily directly callable in the current
    /// host process.
    #[inline]
    pub fn func_addr(&self) -> Option<VmAddr> {
        self.func
    }

    /// VM addresses from the lifecycle function array.
    ///
    /// These addresses are not necessarily directly callable in the current
    /// host process.
    #[inline]
    pub fn func_array_addrs(&self) -> impl Iterator<Item = VmAddr> + '_ {
        self.func_array.as_deref().unwrap_or(&[]).iter().copied()
    }

    /// All lifecycle function VM addresses in call order.
    ///
    /// These addresses are not necessarily directly callable in the current
    /// host process.
    #[inline]
    pub fn func_addrs(&self) -> impl Iterator<Item = VmAddr> + '_ {
        self.func_addr().into_iter().chain(self.func_array_addrs())
    }
}
