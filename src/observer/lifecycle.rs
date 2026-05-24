use crate::{
    elf::Lifecycle,
    os::{HostRegion, RegionAccess, VmAddr},
    segment::ElfSegments,
    sync::Arc,
};
use alloc::boxed::Box;
use core::ptr::NonNull;

/// Lifecycle phase being prepared or executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecyclePhase {
    /// Initialization functions such as `.init` / `.init_array`.
    Init,
    /// Finalization functions such as `.fini` / `.fini_array`.
    Fini,
}

pub(crate) type SharedLifecycleExecutor<R = HostRegion> =
    Arc<dyn for<'a> Fn(&mut LifecycleEvent<'a, R>) + Send + Sync>;

/// Event passed to lifecycle hooks before `.init` / `.fini` functions run.
///
/// The observer may inspect, filter, reorder, or replace the lifecycle function
/// address list before executing it.
pub struct LifecycleEvent<'a, R: RegionAccess = HostRegion> {
    phase: LifecyclePhase,
    lifecycle: Lifecycle,
    segments: &'a ElfSegments<R>,
    executor: SharedLifecycleExecutor<R>,
}

impl<'a, R: RegionAccess> LifecycleEvent<'a, R> {
    #[inline]
    pub(crate) fn new(
        phase: LifecyclePhase,
        lifecycle: &'a Lifecycle,
        segments: &'a ElfSegments<R>,
    ) -> Self {
        Self::with_executor(
            phase,
            lifecycle,
            segments,
            default_lifecycle_executor::<R>(),
        )
    }

    #[inline]
    pub(crate) fn with_executor(
        phase: LifecyclePhase,
        lifecycle: &'a Lifecycle,
        segments: &'a ElfSegments<R>,
        executor: SharedLifecycleExecutor<R>,
    ) -> Self {
        Self {
            phase,
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

    /// Replaces the executor used for this lifecycle event.
    #[inline]
    pub fn set_executor<F>(&mut self, executor: F)
    where
        F: for<'event> Fn(&mut LifecycleEvent<'event, R>) + Send + Sync + 'static,
    {
        self.executor = shared_lifecycle_executor(executor);
    }

    #[inline]
    pub(crate) fn executor(&self) -> SharedLifecycleExecutor<R> {
        self.executor.clone()
    }

    #[inline]
    pub(crate) fn into_lifecycle(self) -> Lifecycle {
        self.lifecycle
    }

    #[inline]
    pub(crate) fn run(&mut self) {
        let executor = self.executor.clone();
        executor(self);
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> NonNull<u8> {
        self.segments
            .host_ptr(addr)
            .expect("lifecycle function address is not backed by host-accessible mapped memory")
    }

    /// All active lifecycle function VM addresses in call order.
    #[inline]
    pub fn vm_addrs(&self) -> impl Iterator<Item = VmAddr> + '_ {
        self.lifecycle.func_addrs()
    }

    /// All active lifecycle function host pointers in call order.
    #[inline]
    pub fn func_addrs(&self) -> impl Iterator<Item = NonNull<u8>> + '_ {
        self.lifecycle.func_addrs().map(|addr| self.host_ptr(addr))
    }
}

#[inline]
pub(crate) fn default_lifecycle_executor<R: RegionAccess>() -> SharedLifecycleExecutor<R> {
    shared_lifecycle_executor(|ctx: &mut LifecycleEvent<'_, R>| {
        ctx.func_addrs().for_each(|ptr| {
            let ptr = ptr.as_ptr() as usize;
            #[cfg(not(windows))]
            unsafe {
                core::mem::transmute::<usize, extern "C" fn()>(ptr)()
            };
            #[cfg(windows)]
            unsafe {
                core::mem::transmute::<usize, extern "sysv64" fn()>(ptr)()
            };
        });
    })
}

#[inline]
pub(crate) fn shared_lifecycle_executor<F, R>(executor: F) -> SharedLifecycleExecutor<R>
where
    F: for<'event> Fn(&mut LifecycleEvent<'event, R>) + Send + Sync + 'static,
    R: RegionAccess,
{
    Arc::from(Box::new(executor)
        as Box<
            dyn for<'event> Fn(&mut LifecycleEvent<'event, R>) + Send + Sync,
        >)
}
