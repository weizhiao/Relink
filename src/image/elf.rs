use crate::{
    Result,
    arch::NativeArch,
    elf::ElfPhdr,
    input::Path,
    relocation::{Relocatable, RelocateArgs, RelocationArch, RelocationHandler, Relocator},
};

use super::{LoadedCore, LoadedExec, RawDylib, RawExec};
#[cfg(feature = "object")]
use super::{LoadedObject, RawObject};

/// A mapped but unrelocated ELF image.
///
/// This is the type returned by [`crate::Loader::load`]. It can hold a raw shared
/// object, executable, or relocatable object depending on the ELF input.
///
/// The optional `Arch` type parameter is forwarded to every variant, including
/// relocatable objects, so a raw image always belongs to one relocation domain.
#[derive(Debug)]
pub enum RawElf<D, Arch = crate::arch::NativeArch>
where
    D: 'static,
    Arch: RelocationArch,
{
    /// A dynamic library (shared object, typically `.so`).
    Dylib(RawDylib<D, Arch>),

    /// An executable file (typically a PIE or non-PIE executable).
    Exec(RawExec<D, Arch>),

    /// A relocatable object file (typically `.o`).
    #[cfg(feature = "object")]
    Object(RawObject<D, Arch>),
}

/// A fully relocated and ready-to-use ELF module.
///
/// This is the result of calling `.relocator().relocate()` on a [`RawElf`].
/// Loaded images retain the dependencies that were actually used during relocation.
#[derive(Debug, Clone)]
pub enum LoadedElf<D: 'static, Arch: RelocationArch = NativeArch> {
    /// A relocated dynamic library.
    Dylib(LoadedCore<D, Arch>),

    /// A relocated executable.
    Exec(LoadedExec<D, Arch>),

    /// A relocated object file.
    #[cfg(feature = "object")]
    Object(LoadedObject<D, Arch>),
}

impl<D: 'static, Arch: RelocationArch> RawElf<D, Arch> {
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
    pub fn relocator(self) -> Relocator<Self, (), (), D, Arch>
    where
        Self: Relocatable<D, Arch = Arch>,
    {
        Relocator::new().with_object(self)
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

    /// Gets the length of the bounding runtime span covered by mapped memory.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        match self {
            RawElf::Dylib(dylib) => dylib.mapped_len(),
            RawElf::Exec(exec) => exec.mapped_len(),
            #[cfg(feature = "object")]
            RawElf::Object(object) => object.mapped_len(),
        }
    }

    /// Returns whether `addr` is inside this image's mapped memory.
    #[inline]
    pub fn contains_addr(&self, addr: usize) -> bool {
        match self {
            RawElf::Dylib(dylib) => dylib.contains_addr(addr),
            RawElf::Exec(exec) => exec.contains_addr(addr),
            #[cfg(feature = "object")]
            RawElf::Object(object) => object.contains_addr(addr),
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
    pub fn base(&self) -> usize {
        match self {
            RawElf::Dylib(dylib) => dylib.base(),
            RawElf::Exec(exec) => exec.base(),
            #[cfg(feature = "object")]
            RawElf::Object(object) => object.base(),
        }
    }
}

impl<D: 'static, Arch: RelocationArch> LoadedElf<D, Arch> {
    /// Converts this LoadedElf into the loaded core for a dylib if it is one.
    ///
    /// # Returns
    /// * `Some(dylib)` - If this is a Dylib variant
    /// * `None` - If this is an Exec variant
    #[inline]
    pub fn into_dylib(self) -> Option<LoadedCore<D, Arch>> {
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
    pub fn into_exec(self) -> Option<LoadedExec<D, Arch>> {
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
    pub fn into_object(self) -> Option<LoadedObject<D, Arch>> {
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
    pub fn as_dylib(&self) -> Option<&LoadedCore<D, Arch>> {
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
    pub fn as_exec(&self) -> Option<&LoadedExec<D, Arch>> {
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
    pub fn as_object(&self) -> Option<&LoadedObject<D, Arch>> {
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

    /// Gets the length of the bounding runtime span covered by mapped memory.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        match self {
            LoadedElf::Dylib(dylib) => dylib.mapped_len(),
            LoadedElf::Exec(exec) => exec.mapped_len(),
            #[cfg(feature = "object")]
            LoadedElf::Object(object) => object.mapped_len(),
        }
    }

    /// Returns whether `addr` is inside this image's mapped memory.
    #[inline]
    pub fn contains_addr(&self, addr: usize) -> bool {
        match self {
            LoadedElf::Dylib(dylib) => dylib.contains_addr(addr),
            LoadedElf::Exec(exec) => exec.contains_addr(addr),
            #[cfg(feature = "object")]
            LoadedElf::Object(object) => object.contains_addr(addr),
        }
    }
}

impl<D: 'static, Arch: RelocationArch> Relocatable<D> for RawElf<D, Arch> {
    type Output = LoadedElf<D, Arch>;
    type Arch = Arch;

    fn relocate<PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, Arch, PreH, PostH>,
    ) -> Result<Self::Output>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
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
