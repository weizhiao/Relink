use super::BindingMode;

/// Reusable relocation settings, including lazy binding and initialization policy.
///
/// Pass a raw image to [`Self::run`], then configure its symbol scopes and observers.
/// Use [`crate::Linker`] when `DT_NEEDED` dependencies should be loaded automatically.
///
/// # Example
///
/// ```rust,no_run
/// use elf_loader::{
///     Loader, Relocator, Result,
///     AddressSpaceId, Domain,
///     image::{SyntheticModule, SyntheticSymbol},
/// };
///
/// extern "C" fn host_log(_value: i32) {}
///
/// fn main() -> Result<()> {
///     let domain = Domain::native(AddressSpaceId::PROCESS);
///     let host = SyntheticModule::new(
///         &domain,
///         "__host",
///         [SyntheticSymbol::function(c"host_log", host_log as *const ())],
///     );
///
///     let raw = Loader::new().run(domain).load_dylib("plugin.so")?;
///     let loaded = Relocator::new()
///         .run(raw)
///         .with_modules([host])?
///         .relocate()?;
///
///     let run = unsafe {
///         loaded
///             .get::<extern "C" fn()>("run")?
///             .expect("symbol `run` not found")
///     };
///     run();
///     Ok(())
/// }
/// ```
#[derive(Clone, Copy)]
pub struct Relocator<Binder = ()> {
    pub(super) lazy_binder: Binder,
    pub(super) run_init: bool,
    pub(super) binding: BindingMode,
}

impl Relocator<()> {
    /// Creates a new empty relocation configuration.
    #[inline]
    pub const fn new() -> Self {
        Self {
            lazy_binder: (),
            run_init: true,
            binding: BindingMode::Default,
        }
    }
}

impl Default for Relocator<()> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<Binder> Relocator<Binder> {
    /// Sets the binding policy inherited by relocation runs.
    ///
    /// `BindingMode::Default` follows the ELF object's binding requirements.
    /// A relocation run may override this policy.
    #[inline]
    pub const fn with_binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }

    /// Overrides the lazy PLT binder used to prepare runtime binding.
    pub const fn with_lazy_binder<NewBinder>(self, binder: NewBinder) -> Relocator<NewBinder>
    where
        Binder: Copy,
    {
        let _ = self.lazy_binder;
        Relocator {
            lazy_binder: binder,
            run_init: self.run_init,
            binding: self.binding,
        }
    }

    /// Leaves image constructors pending after relocation.
    ///
    /// This is useful when an image must be published in an external registry
    /// before its constructors execute.
    #[inline]
    pub const fn defer_init(mut self) -> Self {
        self.run_init = false;
        self
    }
}
