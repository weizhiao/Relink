use super::{TlsBinding, TlsIndex, TlsModuleId, TlsTemplate, TlsTpOffset};
use crate::{
    Result, TlsError,
    memory::{MappedView, VmAddr},
    relocation::RelocationArch,
    runtime::{CodeContext, CodeExecutor, DomainId},
};
use alloc::{boxed::Box, vec::Vec};
use core::fmt;
use spin::Mutex;

/// TLS registration metadata and its runtime entry address.
///
/// The owning [`TlsRegistration`] must outlive every use of this metadata.
/// Cloning or dropping a `TlsModule` does not retain or unregister it.
#[derive(Clone)]
pub struct TlsModule {
    binding: TlsBinding,
    entry: VmAddr,
}

impl fmt::Debug for TlsModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TlsModule").field(&self.binding).finish()
    }
}

impl TlsModule {
    /// Creates registration metadata for a custom runtime.
    ///
    /// # Safety
    /// `binding` must describe a live registration with valid ABI metadata for
    /// `entry`. Keep the runtime and entry fixed and alive for every use, and
    /// transfer cleanup responsibility to a [`TlsRegistration`].
    pub const unsafe fn new(binding: TlsBinding, entry: VmAddr) -> Self {
        Self { binding, entry }
    }

    /// Returns the relocation metadata without transferring ownership.
    pub const fn binding(&self) -> TlsBinding {
        self.binding
    }

    /// Returns the runtime module ID.
    pub const fn mod_id(&self) -> TlsModuleId {
        self.binding.mod_id()
    }

    /// Returns a stable thread-pointer offset, when available.
    pub const fn tp_offset(&self) -> Option<TlsTpOffset> {
        self.binding.tp_offset()
    }

    pub(crate) fn check_domain(&self, domain: DomainId) -> Result<()> {
        if Some(self.entry) != domain.tls_entry() {
            return Err(TlsError::ModuleMismatch.into());
        }
        Ok(())
    }

    /// Returns this registration's runtime ABI entry.
    pub const fn entry(&self) -> VmAddr {
        self.entry
    }

    pub(crate) fn resolve<Arch: RelocationArch>(
        &self,
        executor: &dyn CodeExecutor<Arch>,
        ctx: CodeContext<'_, Arch>,
        offset: usize,
    ) -> Result<VmAddr> {
        executor.resolve_tls(
            ctx,
            self.entry,
            TlsIndex {
                ti_module: self.mod_id(),
                ti_offset: offset.wrapping_sub(Arch::TLS_DTV_OFFSET),
            },
        )
    }
}

/// Owns a TLS registration and unregisters it on drop.
///
/// Keep it alive through module finalization and TLS descriptor cleanup.
/// Cloning [`TlsModule`] does not extend the registration's lifetime.
pub struct TlsRegistration {
    module: TlsModule,
    release: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl TlsRegistration {
    /// Takes ownership of a registration created by a runtime implementation.
    ///
    /// # Safety
    /// `module` must describe a live registration. `release` must take sole
    /// ownership of its cleanup, retain the runtime, and remove that registration
    /// exactly once. It may own a previous guard to compose additional cleanup.
    /// Provider destruction and callbacks must run without registry locks held.
    pub unsafe fn new(module: TlsModule, release: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self {
            module,
            release: Some(Box::new(release)),
        }
    }

    /// Borrows ABI metadata without transferring registration ownership.
    pub fn module(&self) -> &TlsModule {
        &self.module
    }
}

impl fmt::Debug for TlsRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TlsRegistration")
            .field(&self.module)
            .finish()
    }
}

impl Drop for TlsRegistration {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

struct RegisteredTls {
    owner: TlsRegistration,
    image: &'static [u8],
}

/// TLS ownership and descriptor resources retained by the containing image.
pub(crate) struct ImageTlsState {
    descriptors: Mutex<Vec<Box<dyn Send + Sync>>>,
    registration: Option<RegisteredTls>,
}

impl ImageTlsState {
    pub(crate) fn empty() -> Self {
        Self {
            descriptors: Mutex::new(Vec::new()),
            registration: None,
        }
    }

    pub(crate) fn owned(owner: TlsRegistration, image: MappedView<u8>) -> Self {
        Self {
            descriptors: Mutex::new(Vec::new()),
            registration: Some(RegisteredTls {
                owner,
                image: image.as_slice(),
            }),
        }
    }

    pub(crate) fn module(&self) -> Option<&TlsModule> {
        self.registration.as_ref().map(|tls| tls.owner.module())
    }

    /// Copies only the initialized bytes, after relocation has finished.
    pub(crate) fn template(&self) -> Result<TlsTemplate> {
        let tls = self
            .registration
            .as_ref()
            .ok_or(TlsError::TemplateUnavailable)?;
        Ok(TlsTemplate::new(tls.image))
    }

    pub(crate) fn retain_descriptor(&self, state: Option<Box<dyn Send + Sync>>) {
        if let Some(state) = state {
            self.descriptors.lock().push(state);
        }
    }

    /// Called after finalizers, while the mapping and runtime are still alive.
    pub(crate) fn release(&mut self) {
        self.descriptors.get_mut().clear();
        self.registration.take();
    }
}
