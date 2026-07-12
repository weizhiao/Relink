use crate::{
    Result,
    elf::Lifecycle,
    memory::{ImageMemory, VmAddr},
    relocation::RelocationArch,
    runtime::CodeContext,
};
use alloc::boxed::Box;

pub(crate) type LifecycleHook =
    Box<dyn for<'event> Fn(&mut LifecycleEvent<'event>) -> Result<()> + Send + Sync>;

/// Lifecycle behavior retained after relocation.
pub(crate) struct LifecycleRunner {
    lifecycle: Lifecycle,
    hook: Option<LifecycleHook>,
}

/// Initialization and finalization behavior retained by one loaded image.
pub(crate) struct LifecycleHandlers {
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

    #[inline]
    pub(crate) fn into_finalizer(self) -> LifecycleRunner {
        self.finalizer
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
        F: for<'event> Fn(&mut LifecycleEvent<'event>) -> Result<()> + Send + Sync + 'static,
    {
        self.hook = Some(Box::new(hook));
    }

    #[cfg(feature = "object")]
    pub(crate) fn append_hook<F>(&mut self, hook: F)
    where
        F: for<'event> Fn(&mut LifecycleEvent<'event>) -> Result<()> + Send + Sync + 'static,
    {
        let previous = self.hook.take();
        self.hook = Some(Box::new(move |event| {
            if let Some(previous) = previous.as_ref() {
                previous(event)?;
            }
            hook(event)
        }));
    }

    pub(crate) fn run<Arch, F>(&self, name: &str, memory: &dyn ImageMemory, call: F) -> Result<()>
    where
        Arch: RelocationArch,
        F: Fn(CodeContext<'_, Arch>, VmAddr) -> Result<()>,
    {
        let mut event = LifecycleEvent::new(name, &self.lifecycle);
        if let Some(hook) = self.hook.as_ref() {
            hook(&mut event)?;
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
