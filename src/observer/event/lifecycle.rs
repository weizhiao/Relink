use crate::{
    Result,
    arch::NativeArch,
    elf::Lifecycle,
    image::ElfCore,
    memory::{HostRegion, ImageMemory, RegionAccess},
    relocation::RelocationArch,
    runtime::{CodeContext, CodeExecutor},
    segment::ElfSegments,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::boxed::Box;

pub(crate) type FiniHook =
    Box<dyn for<'event> Fn(&mut FiniEvent<'event>) -> Result<()> + Send + Sync>;

/// Finalization state retained until an image is unloaded.
pub(crate) struct Finalizer<Arch: RelocationArch = NativeArch> {
    lifecycle: Lifecycle,
    executor: Arc<dyn CodeExecutor<Arch>>,
    hook: Option<FiniHook>,
}

impl<Arch: RelocationArch> Finalizer<Arch> {
    #[inline]
    pub(crate) const fn new(lifecycle: Lifecycle, executor: Arc<dyn CodeExecutor<Arch>>) -> Self {
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
    pub(crate) fn set_hook<F>(&mut self, hook: F)
    where
        F: for<'event> Fn(&mut FiniEvent<'event>) -> Result<()> + Send + Sync + 'static,
    {
        self.hook = Some(Box::new(hook));
    }

    #[inline]
    pub(crate) fn run<R: RegionAccess>(self, name: &str, segments: &ElfSegments<R>) -> Result<()> {
        let Self {
            lifecycle,
            executor,
            hook,
        } = self;
        let mut event = FiniEvent::new(name, &lifecycle);
        if let Some(hook) = hook {
            hook(&mut event)?;
        }
        let ctx = CodeContext::<Arch>::new(name, segments);
        for addr in event.lifecycle.func_addrs() {
            executor.call_fini(ctx, addr)?;
        }
        Ok(())
    }
}

/// Event passed to finalization hooks before finalization functions run.
///
/// The hook may inspect, filter, reorder, or replace the finalization function
/// address list before executing it.
pub struct FiniEvent<'a> {
    name: &'a str,
    lifecycle: Lifecycle,
}

impl<'a> FiniEvent<'a> {
    #[inline]
    pub(crate) fn new(name: &'a str, lifecycle: &'a Lifecycle) -> Self {
        Self {
            name,
            lifecycle: lifecycle.clone(),
        }
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub const fn name(&self) -> &'a str {
        self.name
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
}

/// Event passed to relocation observers before initialization functions run.
///
/// The observer may inspect, filter, reorder, or replace the lifecycle function
/// address list before executing it.
pub struct InitEvent<
    'a,
    D: 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    core: &'a ElfCore<D, Arch, R, Tls>,
    lifecycle: Lifecycle,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    InitEvent<'a, D, Arch, R, Tls>
{
    #[inline]
    pub(crate) fn new(core: &'a ElfCore<D, Arch, R, Tls>, lifecycle: &'a Lifecycle) -> Self {
        Self {
            core,
            lifecycle: lifecycle.clone(),
        }
    }

    /// Returns the image core associated with this lifecycle event.
    #[inline]
    pub const fn core(&self) -> &'a ElfCore<D, Arch, R, Tls> {
        self.core
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

    #[inline]
    pub(crate) fn run_with(
        &self,
        memory: &dyn ImageMemory,
        executor: &dyn CodeExecutor<Arch>,
    ) -> Result<()> {
        let ctx = CodeContext::<Arch>::new(self.core.name(), memory);
        for addr in self.lifecycle.func_addrs() {
            executor.call_init(ctx, addr)?;
        }
        Ok(())
    }
}
