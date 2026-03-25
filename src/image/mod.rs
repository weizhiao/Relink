//! Public image types returned by the loader and relocation pipeline.
//!
//! `Loader` produces raw image types such as [`RawElf`], [`RawDylib`], and [`RawExec`].
//! Those raw values are mapped into memory but not yet relocated.
//!
//! After calling `.relocator().relocate()`, you get loaded image types such as
//! [`LoadedElf`], [`LoadedDylib`], [`LoadedExec`], and [`LoadedCore`], which expose
//! symbol lookup, metadata, and dependency retention.

use crate::{
    Result,
    elf::ElfPhdr,
    relocation::{BindingOptions, Relocatable, RelocationHandler, Relocator, SymbolLookup},
};
use ::core::fmt::Debug;
use alloc::vec::Vec;

mod core;
mod dylib;
mod dynamic;
mod exec;
#[cfg(feature = "object")]
mod object;
mod symbol;

#[cfg(any(feature = "lazy-binding", feature = "object"))]
pub(crate) use core::CoreInner;
pub(crate) use dynamic::DynamicImage;
#[cfg(not(feature = "lazy-binding"))]
pub(crate) use dynamic::DynamicInfo;
#[cfg(feature = "lazy-binding")]
pub(crate) use dynamic::{DynamicInfo, LazyBindingInfo};

pub use core::{ElfCore, ElfCoreRef, LoadedCore};
pub use dylib::{LoadedDylib, RawDylib};
pub use exec::{LoadedExec, RawExec};
#[cfg(feature = "object")]
pub use object::{LoadedObject, RawObject};
pub use symbol::Symbol;

/// A mapped but unrelocated ELF image.
///
/// This is the type returned by [`crate::Loader::load`]. It can hold a raw shared
/// object, executable, or relocatable object depending on the ELF input.
#[derive(Debug)]
pub enum RawElf<D>
where
    D: 'static,
{
    /// A dynamic library (shared object, typically `.so`).
    Dylib(RawDylib<D>),

    /// An executable file (typically a PIE or non-PIE executable).
    Exec(RawExec<D>),

    /// A relocatable object file (typically `.o`).
    #[cfg(feature = "object")]
    Object(RawObject<D>),
}

/// A fully relocated and ready-to-use ELF module.
///
/// This is the result of calling `.relocator().relocate()` on a [`RawElf`].
/// Loaded images retain the dependencies that were actually used during relocation.
#[derive(Debug, Clone)]
pub enum LoadedElf<D> {
    /// A relocated dynamic library.
    Dylib(LoadedDylib<D>),

    /// A relocated executable.
    Exec(LoadedExec<D>),

    /// A relocated object file.
    #[cfg(feature = "object")]
    Object(LoadedObject<D>),
}

impl<D: 'static> RawElf<D> {
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
    pub fn relocator(self) -> Relocator<Self, (), (), (), (), (), D> {
        Relocator::new(self)
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

    /// Gets the total length of mapped memory for the ELF file
    #[inline]
    pub fn mapped_len(&self) -> usize {
        match self {
            RawElf::Dylib(dylib) => dylib.mapped_len(),
            RawElf::Exec(exec) => exec.mapped_len(),
            #[cfg(feature = "object")]
            RawElf::Object(object) => object.mapped_len(),
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
    pub fn phdrs(&self) -> Option<&[ElfPhdr]> {
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

impl<D> LoadedElf<D> {
    /// Converts this LoadedElf into a LoadedDylib if it is one
    ///
    /// # Returns
    /// * `Some(dylib)` - If this is a Dylib variant
    /// * `None` - If this is an Exec variant
    #[inline]
    pub fn into_dylib(self) -> Option<LoadedDylib<D>> {
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
    pub fn into_exec(self) -> Option<LoadedExec<D>> {
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

    /// Gets a reference to the LoadedDylib if this is one
    ///
    /// # Returns
    /// * `Some(dylib)` - If this is a Dylib variant
    /// * `None` - If this is an Exec variant
    #[inline]
    pub fn as_dylib(&self) -> Option<&LoadedDylib<D>> {
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
    pub fn as_exec(&self) -> Option<&LoadedExec<D>> {
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
}

impl<D: 'static> Relocatable<D> for RawElf<D> {
    type Output = LoadedElf<D>;

    fn relocate<PreS, PostS, LazyS, PreH, PostH>(
        self,
        scope: Vec<LoadedCore<D>>,
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
        binding: BindingOptions<LazyS>,
    ) -> Result<Self::Output>
    where
        D: 'static,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        match self {
            RawElf::Dylib(dylib) => {
                let relocated = Relocatable::relocate(
                    dylib,
                    scope,
                    pre_find,
                    post_find,
                    pre_handler,
                    post_handler,
                    binding,
                )?;
                Ok(LoadedElf::Dylib(relocated))
            }
            RawElf::Exec(exec) => {
                let relocated = Relocatable::relocate(
                    exec,
                    scope,
                    pre_find,
                    post_find,
                    pre_handler,
                    post_handler,
                    binding,
                )?;
                Ok(LoadedElf::Exec(relocated))
            }
            #[cfg(feature = "object")]
            RawElf::Object(relocatable) => {
                let relocated = Relocatable::relocate(
                    relocatable,
                    Vec::new(),
                    pre_find,
                    post_find,
                    pre_handler,
                    post_handler,
                    binding,
                )?;
                Ok(LoadedElf::Object(relocated))
            }
        }
    }
}
