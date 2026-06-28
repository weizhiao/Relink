mod dylib;
mod dynamic;
mod exec;
#[cfg(feature = "object")]
mod object;

use crate::{
    Result,
    arch::NativeArch,
    elf::ElfPhdr,
    image::LoadedCore,
    input::Path,
    lazy::traits::SupportLazy,
    memory::{HostRegion, RegionAccess, VmAddr},
    observer::RelocationObserver,
    relocation::{
        ObjectRelocationArch, Relocatable, RelocateArgs, RelocationArch, RelocationHandler,
        Relocator,
    },
    tls::TlsResolver,
};

pub use dylib::RawDylib;
pub(crate) use dynamic::DynamicInfo;
pub(crate) use dynamic::PltRelocInfo;
pub use dynamic::RawDynamic;
pub(crate) use dynamic::RawDynamicParts;
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
pub enum RawElf<
    D,
    Arch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> where
    D: 'static,
    Arch: ObjectRelocationArch,
{
    /// A dynamic library (shared object, typically `.so`).
    Dylib(RawDylib<D, Arch, R, Tls>),

    /// An executable file (typically a PIE or non-PIE executable).
    Exec(RawExec<D, Arch, R, Tls>),

    /// A relocatable object file (typically `.o`).
    #[cfg(feature = "object")]
    Object(RawObject<D, Arch, R, Tls>),
}

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> SupportLazy
    for RawElf<D, Arch, R, Tls>
{
}

/// A fully relocated and ready-to-use ELF module.
///
/// This is the result of calling `.relocator().relocate()` on a [`RawElf`].
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

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    RawElf<D, Arch, R, Tls>
{
    /// Creates a relocation builder for this raw image.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::Loader;
    ///
    /// let mut loader = Loader::new();
    /// let raw = loader.load("path/to/input.elf").unwrap();
    /// let relocated = raw.relocator().relocate().unwrap();
    /// ```
    pub fn relocator(self) -> Relocator<Self, (), (), Arch, (), Tls>
    where
        Self: Relocatable<D, Arch = Arch, Tls = Tls>,
    {
        Relocator::<(), (), (), Arch, (), Tls>::new().with_object(self)
    }

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

impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Relocatable<D>
    for RawElf<D, Arch, R, Tls>
{
    type Output = LoadedElf<D, Arch, R, Tls>;
    type Arch = Arch;
    type Tls = Tls;

    fn relocate<PreH, PostH, Obs>(
        self,
        args: RelocateArgs<'_, Arch, Tls, PreH, PostH, Obs>,
    ) -> Result<Self::Output>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
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
