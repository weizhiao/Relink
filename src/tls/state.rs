use super::{
    defs::{ModuleTls, TlsImageSource, TlsIndex},
    traits::TlsResolver,
};
use crate::{
    Result,
    memory::{MappedView, VmAddr},
    relocation::RelocationArch,
};
use core::marker::PhantomData;

/// TLS runtime state attached to a loaded ELF core.
///
/// This stores resolver-provided TLS metadata independently of the built-in TLS
/// manager. The `tls` feature only controls the default same-process resolver.
pub(crate) enum CoreTlsState<Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    None(PhantomData<fn() -> (Arch, Tls)>),
    Present {
        module: ModuleTls,
        image: &'static [u8],
        marker: PhantomData<fn() -> (Arch, Tls)>,
    },
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> CoreTlsState<Arch, Tls> {
    #[inline]
    pub(crate) const fn none() -> Self {
        Self::None(PhantomData)
    }

    pub(crate) fn present(module: ModuleTls, image: MappedView<u8>) -> Self {
        assert!(
            module.mod_id().is_some(),
            "present TLS state must have a module ID"
        );
        Self::Present {
            module,
            image: image.as_slice(),
            marker: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn module(&self) -> ModuleTls {
        match self {
            Self::None(_) => ModuleTls::NONE,
            Self::Present { module, .. } => *module,
        }
    }

    #[inline]
    pub(crate) fn cleanup(&self) {
        if let Self::Present { module, .. } = self
            && let Some(mod_id) = module.mod_id()
        {
            Tls::unregister(mod_id);
        }
    }

    #[inline]
    pub(crate) fn has_image(&self) -> bool {
        matches!(self, Self::Present { .. })
    }

    pub(crate) fn with_image(&self, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let Self::Present { image, .. } = self else {
            panic!("TLS image provider must have an image");
        };
        f(image)
    }

    pub(crate) fn init_tls(&self, source: TlsImageSource) -> Result<()> {
        let Self::Present { module, .. } = self else {
            return Ok(());
        };
        let mod_id = module
            .mod_id()
            .expect("present TLS state must have a module ID");
        Tls::init_tls(source, mod_id)
    }

    pub(crate) fn addr(&self, offset: usize) -> Option<VmAddr> {
        let Self::Present { module, .. } = self else {
            return None;
        };
        let ti = TlsIndex {
            ti_module: module.mod_id()?,
            ti_offset: offset.wrapping_sub(Arch::TLS_DTV_OFFSET),
        };
        Tls::resolve_tls_addr(ti).ok()
    }
}
