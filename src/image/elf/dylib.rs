//! Shared-object image types.
//!
//! Use [`RawDylib`] for a mapped-but-unrelocated shared object. Relocation returns
//! the common [`LoadedCore`] representation.

use crate::{
    Result,
    arch::NativeArch,
    image::{LoadedCore, RawDynamic},
    lazy::{LazyBinder, SupportLazy},
    memory::{HostRegion, RegionAccess},
    observer::RelocationObserver,
    relocation::{Relocatable, RelocateArgs, RelocationArch},
    runtime::DomainId,
    tls::TlsResolver,
};
use core::{fmt::Debug, ops::Deref};

/// A mapped but unrelocated shared object.
///
/// Values of this type are returned by [`crate::Loader::load_dylib`]. They expose
/// ELF metadata immediately and can later be turned into a [`LoadedCore`] by running
/// relocation. The wrapper dereferences to [`RawDynamic`], which owns the common
/// implementation for dynamic ELF images.
///
/// The optional `Arch` type parameter selects the target architecture used by
/// [`crate::Relocator::run`]. By default it is [`crate::arch::NativeArch`].
pub struct RawDylib<D, Arch = NativeArch, R: RegionAccess = HostRegion, Tls: TlsResolver<Arch> = ()>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
{
    /// The common part containing basic ELF object information.
    pub(crate) inner: RawDynamic<D, Arch, R, Tls>,
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for RawDylib<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawDylib")
            .field("name", &self.inner.name())
            .field("needed_libs", &self.inner.needed_libs())
            .finish()
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    SupportLazy for RawDylib<D, Arch, R, Tls>
{
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    Relocatable<D> for RawDylib<D, Arch, R, Tls>
{
    type Output = LoadedCore<D, Arch, R, Tls>;
    type Arch = Arch;
    type Tls = Tls;

    #[inline]
    fn domain_id(&self) -> DomainId {
        self.inner.state().domain_id()
    }

    fn relocate<Obs, Binder>(
        self,
        args: RelocateArgs<'_, Arch, Tls, Obs, Binder>,
    ) -> Result<Self::Output>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
        Binder: LazyBinder<Arch> + ?Sized,
    {
        Relocatable::relocate(self.inner, args)
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    RawDylib<D, Arch, R, Tls>
{
    /// Returns a mutable reference to the user data when the core is uniquely owned.
    #[inline]
    pub fn user_data_mut(&mut self) -> Option<&mut D> {
        self.inner.user_data_mut()
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Deref
    for RawDylib<D, Arch, R, Tls>
{
    type Target = RawDynamic<D, Arch, R, Tls>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    From<RawDynamic<D, Arch, R, Tls>> for RawDylib<D, Arch, R, Tls>
{
    #[inline]
    fn from(inner: RawDynamic<D, Arch, R, Tls>) -> Self {
        Self { inner }
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    From<RawDylib<D, Arch, R, Tls>> for RawDynamic<D, Arch, R, Tls>
{
    #[inline]
    fn from(dylib: RawDylib<D, Arch, R, Tls>) -> Self {
        dylib.inner
    }
}
