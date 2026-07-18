use super::{
    defs::{ModuleTls, TlsImageSource, TlsIndex},
    traits::TlsResolver,
};
use crate::{Result, TlsError, memory::MappedView, relocation::RelocationArch};
use core::marker::PhantomData;

/// TLS runtime state attached to a loaded ELF core.
///
/// This stores resolver-provided TLS metadata independently of the built-in TLS
/// manager. The `tls` feature only controls the default same-process resolver.
pub(crate) struct CoreTlsState<Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    resolver: Tls,
    registration: Option<TlsRegistration>,
    arch: PhantomData<fn() -> Arch>,
}

struct TlsRegistration {
    module: ModuleTls,
    image: &'static [u8],
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> CoreTlsState<Arch, Tls> {
    #[inline]
    pub(crate) fn without_module(resolver: Tls) -> Self {
        Self {
            resolver,
            registration: None,
            arch: PhantomData,
        }
    }

    pub(crate) fn with_module(resolver: Tls, module: ModuleTls, image: MappedView<u8>) -> Self {
        Self {
            resolver,
            registration: Some(TlsRegistration {
                module,
                image: image.as_slice(),
            }),
            arch: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn resolver(&self) -> &Tls {
        &self.resolver
    }

    #[inline]
    pub(crate) fn module(&self) -> Option<ModuleTls> {
        self.registration
            .as_ref()
            .map(|registration| registration.module)
    }

    pub(crate) fn with_image(&self, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(TlsError::TemplateUnavailable)?;
        f(registration.image)
    }

    pub(crate) fn publish(&self, source: TlsImageSource) -> Result<()> {
        let Some(registration) = &self.registration else {
            return Ok(());
        };
        self.resolver.publish(source, registration.module.mod_id())
    }

    pub(crate) fn index(&self, offset: usize) -> Option<TlsIndex> {
        let registration = self.registration.as_ref()?;
        Some(TlsIndex {
            ti_module: registration.module.mod_id(),
            ti_offset: offset.wrapping_sub(Arch::TLS_DTV_OFFSET),
        })
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Drop for CoreTlsState<Arch, Tls> {
    fn drop(&mut self) {
        if let Some(registration) = &self.registration {
            self.resolver.unregister(registration.module.mod_id());
        }
    }
}
