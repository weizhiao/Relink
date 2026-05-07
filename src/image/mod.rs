//! Public image types returned by the loader and relocation pipeline.
//!
//! `Loader` produces raw image types such as [`RawElf`], [`RawDynamic`], [`RawDylib`],
//! and [`RawExec`].
//! Those raw values are mapped into memory but not yet relocated.
//!
//! After calling `.relocator().relocate()`, you get loaded image types such as
//! [`LoadedElf`], [`LoadedExec`], and [`LoadedCore`], which expose symbol lookup,
//! metadata, and dependency retention.

use crate::{
    Result,
    arch::NativeArch,
    elf::ElfPhdr,
    relocation::{
        Relocatable, RelocateArgs, RelocationArch, RelocationHandler, Relocator, SymbolLookup,
    },
};
use ::core::fmt::Debug;

mod core;
mod dylib;
mod dynamic;
mod exec;
#[cfg(feature = "object")]
mod object;
mod scanned;
mod symbol;

#[cfg(any(feature = "lazy-binding", feature = "object"))]
pub(crate) use core::CoreInner;
pub(crate) use core::{ModuleProvider, ScopeSymbol};
pub(crate) use dynamic::DynamicInfo;
#[cfg(feature = "lazy-binding")]
pub(crate) use dynamic::LazyBindingInfo;
pub(crate) use dynamic::RawDynamicParts;
pub(crate) use scanned::ScannedDynamicLoadParts;

pub use core::{ElfCore, ElfCoreRef, LoadedCore, LoadedModule};
pub use dylib::RawDylib;
pub use dynamic::RawDynamic;
pub use exec::{LoadedExec, RawExec, StaticExec};
#[cfg(feature = "object")]
pub use object::{LoadedObject, RawObject};
pub use scanned::{
    AnyScannedDynamic, AnyScannedSection, AnySectionHeaders, ModuleCapability, ScannedDynamic,
    ScannedDynamicInfo, ScannedElf, ScannedExec, ScannedSection, ScannedSectionId,
};
pub use symbol::Symbol;

/// A mapped but unrelocated ELF image.
///
/// This is the type returned by [`crate::Loader::load`]. It can hold a raw shared
/// object, executable, or relocatable object depending on the ELF input.
///
/// The optional `Arch` type parameter is forwarded to the dynamic variants
/// ([`RawDylib`], [`RawExec`]). Object files are always relocated with the
/// host's relocation numbering, so the `Object` variant ignores `Arch`.
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
    Object(RawObject<D>),
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
    Object(LoadedObject<D>),
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
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), (), D, Arch> {
        Relocator::new().with_object(self)
    }

    /// Gets the name of the ELF file
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

#[cfg(feature = "lazy-binding")]
impl<D: 'static> crate::relocation::SupportLazy for RawElf<D> {}

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
    pub fn into_object(self) -> Option<LoadedObject<D>> {
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
    pub fn as_object(&self) -> Option<&LoadedObject<D>> {
        match self {
            LoadedElf::Object(object) => Some(object),
            _ => None,
        }
    }

    /// Gets the name of the ELF file
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

    fn relocate<PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, Arch, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyPreS: SymbolLookup + Send + Sync + 'static,
        LazyPostS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
    {
        match self {
            RawElf::Dylib(dylib) => Ok(LoadedElf::Dylib(Relocatable::relocate(dylib, args)?)),
            RawElf::Exec(exec) => Ok(LoadedElf::Exec(Relocatable::relocate(exec, args)?)),
            #[cfg(feature = "object")]
            RawElf::Object(relocatable) => {
                let RelocateArgs { scope, lookup, .. } = args;
                let inner =
                    relocatable.link_impl(scope, lookup.pre_find, lookup.post_find, &(), &())?;
                Ok(LoadedElf::Object(LoadedObject { inner }))
            }
        }
    }
}
