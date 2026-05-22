use crate::os::VmAddr;
use alloc::{boxed::Box, vec::Vec};

/// ELF lifecycle functions associated with `.init`, `.init_array`, `.fini`, or `.fini_array`.
///
/// The loader stores target addresses here rather than host function pointers.
/// Native handlers may convert those addresses into callable function pointers;
/// emulators can execute the same addresses in the guest environment.
pub struct Lifecycle {
    funcs: Box<[VmAddr]>,
}

impl Lifecycle {
    pub(crate) fn new(func: Option<VmAddr>, func_array: Option<Box<[VmAddr]>>) -> Self {
        let len = usize::from(func.is_some()) + func_array.as_ref().map_or(0, |array| array.len());
        let mut funcs = Vec::with_capacity(len);
        funcs.extend(func);
        if let Some(array) = func_array {
            funcs.extend(array);
        }
        Self {
            funcs: funcs.into_boxed_slice(),
        }
    }

    #[inline]
    pub(crate) fn empty() -> Self {
        Self::new(None, None)
    }

    /// All lifecycle function VM addresses in call order.
    ///
    /// These addresses are not necessarily directly callable in the current
    /// host process.
    #[inline]
    pub fn func_addrs(&self) -> impl Iterator<Item = VmAddr> + '_ {
        self.funcs.iter().copied()
    }
}
