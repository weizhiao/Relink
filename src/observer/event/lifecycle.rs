use crate::{
    Result,
    elf::Lifecycle,
    memory::{ImageMemory, VmAddr},
    relocation::RelocationArch,
    runtime::CodeContext,
    sync::{AtomicBool, Ordering},
};
use alloc::boxed::Box;
use core::cell::UnsafeCell;

type LifecycleHookFn =
    Box<dyn for<'event> FnOnce(&mut LifecycleEvent<'event>) -> Result<()> + Send>;

struct LifecycleHook {
    called: AtomicBool,
    hook: UnsafeCell<Option<LifecycleHookFn>>,
}

impl LifecycleHook {
    #[inline]
    fn new(hook: LifecycleHookFn) -> Self {
        Self {
            called: AtomicBool::new(false),
            hook: UnsafeCell::new(Some(hook)),
        }
    }

    fn run(&self, event: &mut LifecycleEvent<'_>) -> Result<()> {
        if self.called.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        // Safety: the atomic flag above guarantees that only one caller can
        // take the hook. Later callers return before touching the cell.
        let hook = unsafe { (&mut *self.hook.get()).take() };
        if let Some(hook) = hook {
            hook(event)?;
        }
        Ok(())
    }
}

// Safety: access to the interior hook is guarded by `called`, so shared
// references cannot take or invoke the one-shot hook more than once.
unsafe impl Sync for LifecycleHook {}

/// Lifecycle behavior retained after relocation.
pub(crate) struct LifecycleRunner {
    lifecycle: Lifecycle,
    hook: Option<LifecycleHook>,
}

/// Initialization and finalization behavior retained by one loaded image.
pub struct LifecycleHandlers {
    initializer: LifecycleRunner,
    finalizer: LifecycleRunner,
}

impl LifecycleHandlers {
    #[inline]
    pub(crate) const fn new(initializer: LifecycleRunner, finalizer: LifecycleRunner) -> Self {
        Self {
            initializer,
            finalizer,
        }
    }

    #[inline]
    pub(crate) const fn initializer(&self) -> &LifecycleRunner {
        &self.initializer
    }

    #[inline]
    pub(crate) const fn initializer_mut(&mut self) -> &mut LifecycleRunner {
        &mut self.initializer
    }

    #[inline]
    pub(crate) const fn finalizer(&self) -> &LifecycleRunner {
        &self.finalizer
    }

    #[inline]
    pub(crate) const fn finalizer_mut(&mut self) -> &mut LifecycleRunner {
        &mut self.finalizer
    }

    /// Returns the initialization lifecycle.
    #[inline]
    pub fn init(&self) -> &Lifecycle {
        self.initializer().lifecycle()
    }

    /// Returns mutable initialization lifecycle addresses.
    #[inline]
    pub fn init_mut(&mut self) -> &mut Lifecycle {
        self.initializer_mut().lifecycle_mut()
    }

    /// Installs a hook that runs immediately before initialization functions.
    #[inline]
    pub fn set_init_hook<F>(&mut self, hook: F)
    where
        F: for<'hook> FnOnce(&mut LifecycleEvent<'hook>) -> Result<()> + Send + 'static,
    {
        self.initializer_mut().set_hook(hook);
    }

    /// Returns the finalization lifecycle.
    #[inline]
    pub fn fini(&self) -> &Lifecycle {
        self.finalizer().lifecycle()
    }

    /// Returns mutable finalization lifecycle addresses.
    #[inline]
    pub fn fini_mut(&mut self) -> &mut Lifecycle {
        self.finalizer_mut().lifecycle_mut()
    }

    /// Installs a hook that runs immediately before finalization functions.
    #[inline]
    pub fn set_fini_hook<F>(&mut self, hook: F)
    where
        F: for<'hook> FnOnce(&mut LifecycleEvent<'hook>) -> Result<()> + Send + 'static,
    {
        self.finalizer_mut().set_hook(hook);
    }
}

impl LifecycleRunner {
    #[inline]
    pub(crate) const fn new(lifecycle: Lifecycle) -> Self {
        Self {
            lifecycle,
            hook: None,
        }
    }

    #[inline]
    pub(crate) const fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }

    #[inline]
    pub(crate) const fn lifecycle_mut(&mut self) -> &mut Lifecycle {
        &mut self.lifecycle
    }

    #[inline]
    pub(crate) fn set_hook<F>(&mut self, hook: F)
    where
        F: for<'event> FnOnce(&mut LifecycleEvent<'event>) -> Result<()> + Send + 'static,
    {
        self.hook = Some(LifecycleHook::new(Box::new(hook)));
    }

    #[cfg(feature = "object")]
    pub(crate) fn append_hook<F>(&mut self, hook: F)
    where
        F: for<'event> FnOnce(&mut LifecycleEvent<'event>) -> Result<()> + Send + 'static,
    {
        let previous = self.hook.take();
        self.hook = Some(LifecycleHook::new(Box::new(move |event| {
            if let Some(previous) = previous {
                previous.run(event)?;
            }
            hook(event)
        })));
    }

    pub(crate) fn run<Arch, F>(&self, name: &str, memory: &dyn ImageMemory, call: F) -> Result<()>
    where
        Arch: RelocationArch,
        F: Fn(CodeContext<'_, Arch>, VmAddr) -> Result<()>,
    {
        let mut event = LifecycleEvent::new(name, &self.lifecycle);
        if let Some(hook) = self.hook.as_ref() {
            hook.run(&mut event)?;
        }
        let ctx = CodeContext::<Arch>::new(name, memory);
        for addr in event.lifecycle.func_addrs() {
            call(ctx, addr)?;
        }
        Ok(())
    }
}

/// Event passed to initialization and finalization hooks.
///
/// A hook may inspect, filter, reorder, or replace the lifecycle function
/// address list before it is executed.
pub struct LifecycleEvent<'event> {
    name: &'event str,
    lifecycle: Lifecycle,
}

impl<'event> LifecycleEvent<'event> {
    #[inline]
    pub(crate) fn new(name: &'event str, lifecycle: &Lifecycle) -> Self {
        Self {
            name,
            lifecycle: lifecycle.clone(),
        }
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub const fn name(&self) -> &'event str {
        self.name
    }

    /// Returns the lifecycle address table for this event.
    #[inline]
    pub const fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }

    /// Returns the mutable lifecycle address table for this event.
    #[inline]
    pub const fn lifecycle_mut(&mut self) -> &mut Lifecycle {
        &mut self.lifecycle
    }
}
