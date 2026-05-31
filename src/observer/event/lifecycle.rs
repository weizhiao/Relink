use crate::{
    MmapError, Result,
    elf::Lifecycle,
    os::{HostRegion, RegionAccess, VmAddr},
    segment::ElfSegments,
};
use alloc::boxed::Box;

/// Lifecycle phase being prepared or executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecyclePhase {
    /// Initialization functions such as `.init` / `.init_array`.
    Init,
    /// Finalization functions such as `.fini` / `.fini_array`.
    Fini,
}

pub(crate) type CodeExecutorBox<R = HostRegion> = Box<dyn CodeExecutor<R>>;
pub(crate) type LifecycleHook<R = HostRegion> =
    Box<dyn for<'event> Fn(&mut LifecycleEvent<'event, R>) -> Result<()> + Send + Sync>;

/// Executes one lifecycle function address for a mapped image.
///
/// Native hosts can call the address through a host pointer. Remote process,
/// guest, kernel-module, or bare-metal environments can provide their own
/// executor that interprets the VM address in their runtime.
pub trait CodeExecutor<R: RegionAccess = HostRegion>: Send + Sync + 'static {
    /// Executes one lifecycle function address.
    fn call_void(&self, event: &LifecycleEvent<'_, R>, addr: VmAddr) -> Result<()>;
}

/// Lifecycle executor for images mapped into the current process.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeCodeExecutor;

impl<R: RegionAccess> CodeExecutor<R> for NativeCodeExecutor {
    #[inline]
    fn call_void(&self, event: &LifecycleEvent<'_, R>, addr: VmAddr) -> Result<()> {
        let ptr = event
            .segments
            .host_ptr(addr)
            .ok_or(MmapError::HostPointerUnavailable)?;
        let ptr = ptr.as_ptr() as usize;
        #[cfg(not(windows))]
        unsafe {
            core::mem::transmute::<usize, extern "C" fn()>(ptr)()
        };
        #[cfg(windows)]
        unsafe {
            core::mem::transmute::<usize, extern "sysv64" fn()>(ptr)()
        };
        Ok(())
    }
}

/// Lifecycle executor that intentionally skips every function address.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopCodeExecutor;

impl<R: RegionAccess> CodeExecutor<R> for NoopCodeExecutor {
    #[inline]
    fn call_void(&self, _event: &LifecycleEvent<'_, R>, _addr: VmAddr) -> Result<()> {
        Ok(())
    }
}

/// Finalization state retained until an image is unloaded.
pub(crate) struct Finalizer<R: RegionAccess = HostRegion> {
    lifecycle: Lifecycle,
    executor: CodeExecutorBox<R>,
    hook: Option<LifecycleHook<R>>,
}

impl<R: RegionAccess> Finalizer<R> {
    #[inline]
    pub(crate) const fn new(lifecycle: Lifecycle, executor: CodeExecutorBox<R>) -> Self {
        Self {
            lifecycle,
            executor,
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
    pub(crate) fn set_executor<E>(&mut self, executor: E)
    where
        E: CodeExecutor<R>,
    {
        self.executor = Box::new(executor);
    }

    #[inline]
    pub(crate) fn set_hook<F>(&mut self, hook: F)
    where
        F: for<'event> Fn(&mut LifecycleEvent<'event, R>) -> Result<()> + Send + Sync + 'static,
    {
        self.hook = Some(Box::new(hook));
    }

    #[inline]
    pub(crate) fn run(
        self,
        phase: LifecyclePhase,
        name: &str,
        segments: &ElfSegments<R>,
    ) -> Result<()> {
        let Self {
            lifecycle,
            executor,
            hook,
        } = self;
        let mut event = LifecycleEvent::with_executor(phase, name, &lifecycle, segments, executor);
        if let Some(hook) = hook {
            hook(&mut event)?;
        }
        event.run()
    }
}

/// Event passed to lifecycle hooks before `.init` / `.fini` functions run.
///
/// The observer may inspect, filter, reorder, or replace the lifecycle function
/// address list before executing it.
pub struct LifecycleEvent<'a, R: RegionAccess = HostRegion> {
    phase: LifecyclePhase,
    name: &'a str,
    lifecycle: Lifecycle,
    segments: &'a ElfSegments<R>,
    executor: CodeExecutorBox<R>,
}

impl<'a, R: RegionAccess> LifecycleEvent<'a, R> {
    #[inline]
    pub(crate) fn with_executor(
        phase: LifecyclePhase,
        name: &'a str,
        lifecycle: &'a Lifecycle,
        segments: &'a ElfSegments<R>,
        executor: CodeExecutorBox<R>,
    ) -> Self {
        Self {
            phase,
            name,
            lifecycle: lifecycle.clone(),
            segments,
            executor,
        }
    }

    /// Returns the lifecycle phase associated with this event.
    #[inline]
    pub const fn phase(&self) -> LifecyclePhase {
        self.phase
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// Returns the load base used by this image.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.segments.base()
    }

    /// Returns the lifecycle address table for this event.
    #[inline]
    pub fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }

    /// Returns the mutable lifecycle address table for this event.
    #[inline]
    pub fn lifecycle_mut(&mut self) -> &mut Lifecycle {
        &mut self.lifecycle
    }

    /// Replaces the code executor used to call each lifecycle function.
    #[inline]
    pub fn set_executor<E>(&mut self, executor: E)
    where
        E: CodeExecutor<R>,
    {
        self.executor = Box::new(executor);
    }

    #[inline]
    pub(crate) fn run(&mut self) -> Result<()> {
        for addr in self.lifecycle.func_addrs() {
            self.executor.call_void(self, addr)?;
        }
        Ok(())
    }
}

#[inline]
pub(crate) fn default_lifecycle_executor<R: RegionAccess>() -> CodeExecutorBox<R> {
    Box::new(NativeCodeExecutor)
}

#[inline]
pub(crate) fn noop_lifecycle_executor<R: RegionAccess>() -> CodeExecutorBox<R> {
    Box::new(NoopCodeExecutor)
}
