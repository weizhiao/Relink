use crate::{os::TargetAddr, sync::Arc};
use alloc::boxed::Box;
use core::{marker::PhantomData, slice};

pub(crate) type LifecycleArray = Arc<Box<[TargetAddr]>>;

/// ELF lifecycle functions associated with `.init`, `.init_array`, `.fini`, or `.fini_array`.
///
/// The loader stores target addresses here rather than host function pointers.
/// Native handlers may convert those addresses into callable function pointers;
/// emulators can execute the same addresses in the guest environment.
#[derive(Clone)]
pub struct Lifecycle<'a> {
    func: Option<TargetAddr>,
    func_array: Option<LifecycleArray>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Lifecycle<'a> {
    #[inline]
    pub(crate) fn new(func: Option<TargetAddr>, func_array: Option<LifecycleArray>) -> Self {
        Self {
            func,
            func_array,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn empty() -> Self {
        Self::new(None, None)
    }

    pub(crate) fn array_from_addrs(addrs: impl IntoIterator<Item = TargetAddr>) -> LifecycleArray {
        Arc::new(addrs.into_iter().collect::<Box<[_]>>())
    }

    /// Returns the single initialization/finalization function as a native
    /// function pointer.
    ///
    /// This is only meaningful when target memory is executable in the current
    /// host process.
    #[inline]
    pub fn func(&self) -> Option<fn()> {
        self.func_addr()
            .map(|addr| unsafe { core::mem::transmute::<usize, fn()>(addr) })
    }

    /// Returns the array of initialization/finalization functions as native
    /// function pointers.
    ///
    /// This is only meaningful when target memory is executable in the current
    /// host process. Prefer [`func_array_addrs`](Self::func_array_addrs) for
    /// emulator integrations.
    #[inline]
    pub fn func_array(&self) -> Option<&[fn()]> {
        let addrs = self.func_array.as_ref()?.as_ref().as_ref();
        Some(unsafe { slice::from_raw_parts(addrs.as_ptr().cast::<fn()>(), addrs.len()) })
    }

    /// Address of the single lifecycle function, if present.
    #[inline]
    pub fn func_addr(&self) -> Option<usize> {
        self.func.map(TargetAddr::get)
    }

    /// Target address of the single lifecycle function, if present.
    #[inline]
    pub fn target_func_addr(&self) -> Option<TargetAddr> {
        self.func
    }

    /// Target addresses from the lifecycle function array.
    #[inline]
    pub fn target_func_array_addrs(&self) -> impl Iterator<Item = TargetAddr> + '_ {
        self.func_array
            .as_ref()
            .map(|array| array.as_ref().as_ref())
            .unwrap_or(&[])
            .iter()
            .copied()
    }

    /// Addresses from the lifecycle function array.
    #[inline]
    pub fn func_array_addrs(&self) -> impl Iterator<Item = usize> + '_ {
        self.target_func_array_addrs().map(TargetAddr::get)
    }

    /// All lifecycle function addresses in call order.
    #[inline]
    pub fn func_addrs(&self) -> impl Iterator<Item = usize> + '_ {
        self.func_addr().into_iter().chain(self.func_array_addrs())
    }
}
