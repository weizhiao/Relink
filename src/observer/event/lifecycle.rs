use crate::{
    Result,
    arch::NativeArch,
    elf::Lifecycle,
    os::{
        CodeContext, CodeExecutor, HostRegion, ImageMemory, NativeCodeExecutor, RegionAccess,
        VmAddr,
    },
    relocation::RelocationArch,
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

pub(crate) type CodeExecutorBox<Arch = NativeArch, R = HostRegion> = Box<dyn CodeExecutor<Arch, R>>;
pub(crate) type LifecycleHook<Arch = NativeArch, R = HostRegion> =
    Box<dyn for<'event> Fn(&mut LifecycleEvent<'event, Arch, R>) -> Result<()> + Send + Sync>;

/// Finalization state retained until an image is unloaded.
pub(crate) struct Finalizer<Arch: RelocationArch = NativeArch, R: RegionAccess = HostRegion> {
    lifecycle: Lifecycle,
    executor: CodeExecutorBox<Arch, R>,
    hook: Option<LifecycleHook<Arch, R>>,
}

impl<Arch: RelocationArch, R: RegionAccess> Finalizer<Arch, R> {
    #[inline]
    pub(crate) const fn new(lifecycle: Lifecycle, executor: CodeExecutorBox<Arch, R>) -> Self {
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
        E: CodeExecutor<Arch, R>,
    {
        self.executor = Box::new(executor);
    }

    #[inline]
    pub(crate) fn set_hook<F>(&mut self, hook: F)
    where
        F: for<'event> Fn(&mut LifecycleEvent<'event, Arch, R>) -> Result<()>
            + Send
            + Sync
            + 'static,
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
pub struct LifecycleEvent<'a, Arch: RelocationArch = NativeArch, R: RegionAccess = HostRegion> {
    phase: LifecyclePhase,
    name: &'a str,
    lifecycle: Lifecycle,
    memory: &'a dyn ImageMemory,
    executor: CodeExecutorBox<Arch, R>,
}

impl<'a, Arch: RelocationArch, R: RegionAccess> LifecycleEvent<'a, Arch, R> {
    #[inline]
    pub(crate) fn with_executor(
        phase: LifecyclePhase,
        name: &'a str,
        lifecycle: &'a Lifecycle,
        memory: &'a dyn ImageMemory,
        executor: CodeExecutorBox<Arch, R>,
    ) -> Self {
        Self {
            phase,
            name,
            lifecycle: lifecycle.clone(),
            memory,
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
        self.memory.base()
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
        E: CodeExecutor<Arch, R>,
    {
        self.executor = Box::new(executor);
    }

    #[inline]
    pub(crate) fn run(&mut self) -> Result<()> {
        let ctx = CodeContext::<Arch, R>::new(self.name, self.memory);
        for addr in self.lifecycle.func_addrs() {
            self.executor.call_void(ctx, addr)?;
        }
        Ok(())
    }
}

#[inline]
pub(crate) fn default_lifecycle_executor<Arch: RelocationArch, R: RegionAccess>()
-> CodeExecutorBox<Arch, R> {
    Box::new(NativeCodeExecutor)
}
