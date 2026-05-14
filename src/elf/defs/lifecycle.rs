/// ELF lifecycle functions associated with `.init`, `.init_array`, `.fini`, or `.fini_array`.
#[derive(Clone, Copy)]
pub struct Lifecycle<'a> {
    func: Option<fn()>,
    func_array: Option<&'a [fn()]>,
}

impl<'a> Lifecycle<'a> {
    #[inline]
    pub(crate) const fn new(func: Option<fn()>, func_array: Option<&'a [fn()]>) -> Self {
        Self { func, func_array }
    }

    #[inline]
    pub(crate) const fn empty() -> Self {
        Self::new(None, None)
    }

    /// Returns the single initialization/finalization function.
    #[inline]
    pub fn func(&self) -> Option<fn()> {
        self.func
    }

    /// Returns the array of initialization/finalization functions.
    #[inline]
    pub fn func_array(&self) -> Option<&'a [fn()]> {
        self.func_array
    }

    /// Address of the single lifecycle function, if present.
    #[inline]
    pub fn func_addr(&self) -> Option<usize> {
        self.func.map(|func| func as usize)
    }

    /// Addresses from the lifecycle function array.
    #[inline]
    pub fn func_array_addrs(&self) -> impl Iterator<Item = usize> + '_ {
        self.func_array
            .unwrap_or(&[])
            .iter()
            .map(|func| *func as usize)
    }
}
