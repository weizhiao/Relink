/// Reusable relocation configuration.
///
/// A `Relocator` stores the stable parts of relocation policy: lazy binder.
/// Attach a raw image with
/// [`Relocator::run`] to create a [`RelocatorRun`] that owns per-run state such
/// as the object, observer, and symbol scope.
pub struct Relocator<Binder = ()> {
    pub(super) lazy_binder: Binder,
}

impl<Binder> Clone for Relocator<Binder>
where
    Binder: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            lazy_binder: self.lazy_binder.clone(),
        }
    }
}

impl Relocator<()> {
    /// Creates a new empty relocation configuration.
    #[inline]
    pub const fn new() -> Self {
        Self { lazy_binder: () }
    }
}

impl Default for Relocator<()> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<Binder> Relocator<Binder> {
    /// Overrides the lazy PLT binder used to prepare runtime binding.
    pub const fn lazy_binder<NewBinder>(self, binder: NewBinder) -> Relocator<NewBinder>
    where
        Binder: Copy,
    {
        let _ = self.lazy_binder;
        Relocator {
            lazy_binder: binder,
        }
    }
}
