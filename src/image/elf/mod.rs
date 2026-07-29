mod dylib;
mod dynamic;
mod exec;
#[cfg(feature = "object")]
mod object;

use crate::{
    Result,
    arch::NativeArch,
    elf::ElfPhdr,
    image::{LoadedCore, Module},
    input::Path,
    lazy::{LazyBinder, SupportLazy},
    memory::{HostRegion, RegionAccess, VmAddr},
    observer::RelocationObserver,
    relocation::{ObjectArch, Relocatable, RelocateArgs, RelocationArch},
    runtime::DomainId,
    tls::TlsResolver,
};

pub use dylib::RawDylib;
pub(crate) use dynamic::DynamicInfo;
pub(crate) use dynamic::PltRelocInfo;
pub use dynamic::RawDynamic;
pub use exec::{LoadedExec, RawExec, StaticExec};
#[cfg(feature = "object")]
pub use object::{LoadedObject, RawObject};

/// A mapped but unrelocated ELF image.
///
/// This is the type returned by [`crate::Loader::load`]. It can hold a raw shared
/// object, executable, or relocatable object depending on the ELF input.
///
/// The optional `Arch` type parameter is forwarded to every variant, including
/// relocatable objects, so a raw image always belongs to one relocation domain.
#[derive(Debug)]
pub enum RawElf<D, Arch = NativeArch, R: RegionAccess = HostRegion, Tls: TlsResolver<Arch> = ()>
where
    D: 'static,
    Arch: ObjectArch,
{
    /// A dynamic library (shared object, typically `.so`).
    Dylib(RawDylib<D, Arch, R, Tls>),

    /// An executable file (typically a PIE or non-PIE executable).
    Exec(RawExec<D, Arch, R, Tls>),

    /// A relocatable object file (typically `.o`).
    #[cfg(feature = "object")]
    Object(RawObject<D, Arch, R, Tls>),
}

impl<D: 'static, Arch: ObjectArch, R: RegionAccess, Tls: TlsResolver<Arch>> SupportLazy
    for RawElf<D, Arch, R, Tls>
{
}

/// A fully relocated and ready-to-use ELF module.
///
/// This is the result of relocating a [`RawElf`] with [`crate::Relocator`].
/// Loaded images retain the dependencies that were actually used during relocation.
#[derive(Debug)]
pub enum LoadedElf<
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    /// A relocated dynamic library.
    Dylib(LoadedCore<D, Arch, R, Tls>),

    /// A relocated executable.
    Exec(LoadedExec<D, Arch, R, Tls>),

    /// A relocated object file.
    #[cfg(feature = "object")]
    Object(LoadedObject<D, Arch, R, Tls>),
}

// Keep this impl manual so cloning a loaded image wrapper does not require D, Arch, or R to be Clone.
impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for LoadedElf<D, Arch, R, Tls>
{
    #[inline]
    fn clone(&self) -> Self {
        match self {
            Self::Dylib(dylib) => Self::Dylib(dylib.clone()),
            Self::Exec(exec) => Self::Exec(exec.clone()),
            #[cfg(feature = "object")]
            Self::Object(object) => Self::Object(object.clone()),
        }
    }
}

impl<D: 'static, Arch: ObjectArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    RawElf<D, Arch, R, Tls>
{
    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        match self {
            RawElf::Dylib(dylib) => dylib.path(),
            RawElf::Exec(exec) => exec.path(),
            #[cfg(feature = "object")]
            RawElf::Object(object) => object.path(),
        }
    }

    /// Gets the ELF image identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        match self {
            RawElf::Dylib(dylib) => dylib.name(),
            RawElf::Exec(exec) => exec.name(),
            #[cfg(feature = "object")]
            RawElf::Object(object) => object.name(),
        }
    }

    /// Returns the entry point of the ELF file.
    #[inline]
    pub fn entry(&self) -> usize {
        match self {
            RawElf::Dylib(dylib) => dylib.entry(),
            RawElf::Exec(exec) => exec.entry(),
            #[cfg(feature = "object")]
            RawElf::Object(_) => 0,
        }
    }

    /// Returns the PT_INTERP value.
    #[inline]
    pub fn interp(&self) -> Option<&str> {
        match self {
            RawElf::Dylib(dylib) => dylib.interp(),
            RawElf::Exec(exec) => exec.interp(),
            #[cfg(feature = "object")]
            RawElf::Object(_) => None,
        }
    }

    /// Returns the program headers of the ELF file.
    #[inline]
    pub fn phdrs(&self) -> Option<&[ElfPhdr<Arch::Layout>]> {
        match self {
            RawElf::Dylib(dylib) => Some(dylib.phdrs()),
            RawElf::Exec(exec) => exec.phdrs(),
            #[cfg(feature = "object")]
            RawElf::Object(_) => None,
        }
    }

    /// Returns the base address of the ELF file.
    #[inline]
    pub fn base(&self) -> VmAddr {
        match self {
            RawElf::Dylib(dylib) => dylib.base(),
            RawElf::Exec(exec) => exec.base(),
            #[cfg(feature = "object")]
            RawElf::Object(object) => object.base(),
        }
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    LoadedElf<D, Arch, R, Tls>
{
    /// Converts this LoadedElf into the loaded core for a dylib if it is one.
    ///
    /// # Returns
    /// * `Some(dylib)` - If this is a Dylib variant
    /// * `None` - If this is an Exec variant
    #[inline]
    pub fn into_dylib(self) -> Option<LoadedCore<D, Arch, R, Tls>> {
        match self {
            LoadedElf::Dylib(dylib) => Some(dylib),
            _ => None,
        }
    }

    /// Converts this LoadedElf into a LoadedExec if it is one
    ///
    /// # Returns
    /// * `Some(exec)` - If this is an Exec variant
    /// * `None` - If this is a Dylib variant
    #[inline]
    pub fn into_exec(self) -> Option<LoadedExec<D, Arch, R, Tls>> {
        match self {
            LoadedElf::Exec(exec) => Some(exec),
            _ => None,
        }
    }

    /// Converts this LoadedElf into a LoadedObject if it is one
    ///
    /// # Returns
    /// * `Some(object)` - If this is an Object variant
    /// * `None` - If this is a Dylib or Exec variant
    #[cfg(feature = "object")]
    #[inline]
    pub fn into_object(self) -> Option<LoadedObject<D, Arch, R, Tls>> {
        match self {
            LoadedElf::Object(object) => Some(object),
            _ => None,
        }
    }

    /// Gets a reference to the loaded core for a dylib if this is one.
    ///
    /// # Returns
    /// * `Some(dylib)` - If this is a Dylib variant
    /// * `None` - If this is an Exec variant
    #[inline]
    pub fn as_dylib(&self) -> Option<&LoadedCore<D, Arch, R, Tls>> {
        match self {
            LoadedElf::Dylib(dylib) => Some(dylib),
            _ => None,
        }
    }

    /// Gets a reference to the LoadedExec if this is one
    ///
    /// # Returns
    /// * `Some(exec)` - If this is an Exec variant
    /// * `None` - If this is a Dylib variant
    #[inline]
    pub fn as_exec(&self) -> Option<&LoadedExec<D, Arch, R, Tls>> {
        match self {
            LoadedElf::Exec(exec) => Some(exec),
            _ => None,
        }
    }

    /// Gets a reference to the LoadedObject if this is one
    ///
    /// # Returns
    /// * `Some(object)` - If this is an Object variant
    /// * `None` - If this is a Dylib or Exec variant
    #[cfg(feature = "object")]
    #[inline]
    pub fn as_object(&self) -> Option<&LoadedObject<D, Arch, R, Tls>> {
        match self {
            LoadedElf::Object(object) => Some(object),
            _ => None,
        }
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        match self {
            LoadedElf::Dylib(dylib) => dylib.path(),
            LoadedElf::Exec(exec) => exec.path(),
            #[cfg(feature = "object")]
            LoadedElf::Object(object) => object.path(),
        }
    }

    /// Gets the ELF image identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        match self {
            LoadedElf::Dylib(dylib) => dylib.name(),
            LoadedElf::Exec(exec) => exec.name(),
            #[cfg(feature = "object")]
            LoadedElf::Object(object) => object.name(),
        }
    }

    /// Returns whether `addr` is inside this image's mapped memory.
    #[inline]
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
        match self {
            LoadedElf::Dylib(dylib) => dylib.segments().contains_addr(addr),
            LoadedElf::Exec(exec) => exec.contains_addr(addr),
            #[cfg(feature = "object")]
            LoadedElf::Object(object) => object.segments().contains_addr(addr),
        }
    }
}

impl<D: 'static, Arch: ObjectArch, R: RegionAccess, Tls: TlsResolver<Arch>> Relocatable<D>
    for RawElf<D, Arch, R, Tls>
{
    type Output = LoadedElf<D, Arch, R, Tls>;
    type Arch = Arch;
    type Tls = Tls;

    fn domain_id(&self) -> DomainId {
        match self {
            Self::Dylib(dylib) => Relocatable::domain_id(dylib),
            Self::Exec(exec) => Relocatable::domain_id(exec),
            #[cfg(feature = "object")]
            Self::Object(object) => Relocatable::domain_id(object),
        }
    }

    fn relocate<Obs, Binder>(
        self,
        args: RelocateArgs<'_, Arch, Tls, Obs, Binder>,
    ) -> Result<Self::Output>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
        Binder: LazyBinder<Arch> + ?Sized,
    {
        match self {
            RawElf::Dylib(dylib) => Ok(LoadedElf::Dylib(Relocatable::relocate(dylib, args)?)),
            RawElf::Exec(exec) => Ok(LoadedElf::Exec(Relocatable::relocate(exec, args)?)),
            #[cfg(feature = "object")]
            RawElf::Object(relocatable) => {
                Ok(LoadedElf::Object(Relocatable::relocate(relocatable, args)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NonCloneData;

    #[test]
    fn loaded_elf_clone_does_not_require_user_data_clone() {
        fn assert_clone<T: Clone>() {}

        assert_clone::<LoadedElf<NonCloneData>>();
    }
}
