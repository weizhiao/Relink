use crate::memory::VmAddr;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// ELF lifecycle functions associated with `.init`, `.init_array`, `.fini`, or `.fini_array`.
///
/// The loader stores target addresses here rather than host function pointers.
/// Native handlers may convert those addresses into callable function pointers;
/// guest runtimes can execute the same addresses in their own environment.
#[derive(Clone, Debug, Default)]
pub struct Lifecycle {
    funcs: Vec<VmAddr>,
}

impl Lifecycle {
    pub(crate) fn new(func: Option<VmAddr>, func_array: Option<Box<[VmAddr]>>) -> Self {
        let len = usize::from(func.is_some()) + func_array.as_ref().map_or(0, |array| array.len());
        let mut funcs = Vec::with_capacity(len);
        funcs.extend(func);
        if let Some(array) = func_array {
            funcs.extend(array);
        }
        Self { funcs }
    }

    /// All lifecycle function VM addresses in call order.
    ///
    /// These addresses are not necessarily directly callable in the current
    /// host process.
    #[inline]
    pub fn func_addrs(&self) -> impl Iterator<Item = VmAddr> + '_ {
        self.funcs.iter().copied()
    }

    /// Returns the lifecycle function VM addresses in call order.
    #[inline]
    pub fn as_slice(&self) -> &[VmAddr] {
        &self.funcs
    }

    /// Returns mutable lifecycle function VM addresses in call order.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [VmAddr] {
        &mut self.funcs
    }

    /// Appends a lifecycle function VM address.
    #[inline]
    pub fn push(&mut self, addr: VmAddr) {
        self.funcs.push(addr);
    }

    /// Extends the lifecycle function list with additional VM addresses.
    #[inline]
    pub fn extend<I>(&mut self, addrs: I)
    where
        I: IntoIterator<Item = VmAddr>,
    {
        self.funcs.extend(addrs);
    }

    /// Retains only lifecycle functions accepted by the predicate.
    #[inline]
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(VmAddr) -> bool,
    {
        self.funcs.retain(|addr| f(*addr));
    }

    /// Removes all lifecycle function VM addresses.
    #[inline]
    pub fn clear(&mut self) {
        self.funcs.clear();
    }

    /// Returns whether this lifecycle has no functions to run.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.funcs.is_empty()
    }
}
