/// Reusable configuration for relocating one raw image at a time.
///
/// A `Relocator` stores the stable relocation policy, currently the lazy PLT
/// binder. Attach a raw image with [`Relocator::run`] to create a
/// [`RelocatorRun`](crate::RelocatorRun); the run then owns per-image state such
/// as the raw object, observer, and symbol scope.
///
/// Use `Relocator` directly when the caller already knows which modules should
/// be visible. Use [`Linker`](crate::Linker) when dependencies should be
/// discovered from `DT_NEEDED` entries before relocation.
///
/// # Example
///
/// ```rust,no_run
/// use elf_loader::{
///     Loader, Relocator, Result,
///     image::{SyntheticModule, SyntheticSymbol},
/// };
///
/// extern "C" fn host_log(_value: i32) {}
///
/// fn main() -> Result<()> {
///     let host = SyntheticModule::new(
///         "__host",
///         [SyntheticSymbol::function("host_log", host_log as *const ())],
///     );
///
///     let raw = Loader::new().load_dylib("plugin.so")?;
///     let loaded = Relocator::new()
///         .run(raw)
///         .scope([host])
///         .relocate()?;
///
///     let run = unsafe {
///         loaded
///             .get::<extern "C" fn()>("run")
///             .expect("symbol `run` not found")
///     };
///     run();
///     Ok(())
/// }
/// ```
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

impl<Binder> Copy for Relocator<Binder> where Binder: Copy {}

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
