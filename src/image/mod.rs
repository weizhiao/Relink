//! ELF file format handling
//!
//! This module provides the core data structures and functionality for working
//! with ELF files in various stages of processing: from raw ELF files to
//! relocated and loaded libraries or executables.

use crate::{
    LoadHook, Loader, Result,
    input::IntoElfReader,
    os::Mmap,
    relocation::{Relocatable, RelocationHandler, Relocator, SymbolLookup},
};
use alloc::vec::Vec;
use core::fmt::Debug;
use elf::abi::{PT_DYNAMIC, PT_INTERP};

mod builder;
mod common;
mod kinds;

pub(crate) use builder::{ImageBuilder, ObjectBuilder};
pub(crate) use common::{CoreInner, DynamicImage};
pub(crate) use kinds::StaticImage;

pub use common::{ElfCore, ElfCoreRef, LoadedCore, Symbol};
pub use kinds::{LoadedDylib, LoadedExec, LoadedObject, RawDylib, RawExec, RawObject};

/// A mapped but unrelocated ELF image.
///
/// This enum represents an ELF file that has been loaded into memory (mapped)
/// but has not yet undergone the relocation process. It can be a dynamic library,
/// an executable, or a relocatable object file.
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
    Object(RawObject<D>),
}

/// A fully relocated and ready-to-use ELF module.
///
/// This enum represents an ELF file that has been loaded, mapped, and had all
/// its relocations resolved. It is now ready for symbol lookup or execution.
///
/// It maintains internal reference counts to its dependencies to ensure
/// memory safety during its lifetime.
#[derive(Debug, Clone)]
pub enum LoadedElf<D> {
    /// A relocated dynamic library.
    Dylib(LoadedDylib<D>),

    /// A relocated executable.
    Exec(LoadedExec<D>),

    /// A relocated object file.
    Object(LoadedObject<D>),
}

impl<D: 'static> RawElf<D> {
    /// Creates a builder for relocating the ELF file.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, input::ElfBinary};
    ///
    /// let mut loader = Loader::new();
    /// let bytes = &[]; // ELF file bytes
    /// let lib = loader.load_dylib(ElfBinary::new("liba.so", bytes)).unwrap();
    ///
    /// let relocated = lib.relocator()
    ///     .lazy(true)
    ///     .relocate()
    ///     .unwrap();
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
            RawElf::Object(object) => object.name(),
        }
    }

    /// Gets the total length of mapped memory for the ELF file
    #[inline]
    pub fn mapped_len(&self) -> usize {
        match self {
            RawElf::Dylib(dylib) => dylib.mapped_len(),
            RawElf::Exec(exec) => exec.mapped_len(),
            RawElf::Object(object) => object.mapped_len(),
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
        lazy: Option<bool>,
        lazy_scope: Option<LazyS>,
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
                    lazy,
                    lazy_scope,
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
                    lazy,
                    lazy_scope,
                )?;
                Ok(LoadedElf::Exec(relocated))
            }
            RawElf::Object(relocatable) => {
                let relocated = Relocatable::relocate(
                    relocatable,
                    Vec::new(),
                    pre_find,
                    post_find,
                    pre_handler,
                    post_handler,
                    lazy,
                    None::<LazyS>, // ElfRelocatable always uses LazyScope<(), ()>, so pass None
                )?;
                Ok(LoadedElf::Object(relocated))
            }
        }
    }
}

impl<M: Mmap, H: LoadHook<D>, D: Default + 'static> Loader<M, H, D> {
    /// Load an ELF file into memory
    ///
    /// # Arguments
    /// * `object` - The ELF object to load
    ///
    /// # Returns
    /// * `Ok(Elf)` - The loaded ELF file
    /// * `Err(Error)` - If loading fails
    pub fn load<'a, I>(&mut self, input: I) -> Result<RawElf<D>>
    where
        I: IntoElfReader<'a>,
    {
        let mut object = input.into_reader()?;
        let ehdr = self.buf.prepare_ehdr(&mut object)?;

        match ehdr.e_type {
            elf::abi::ET_REL => Ok(RawElf::Object(self.load_object_internal(object)?)),
            elf::abi::ET_EXEC => Ok(RawElf::Exec(self.load_exec_impl(object)?)),
            elf::abi::ET_DYN => {
                let phdrs = self.buf.prepare_phdrs(&ehdr, &mut object)?;
                let has_dynamic = phdrs.iter().any(|p| p.p_type == PT_DYNAMIC);
                let is_pie = phdrs.iter().any(|p| p.p_type == PT_INTERP) || !has_dynamic;
                if is_pie {
                    Ok(RawElf::Exec(self.load_exec_impl(object)?))
                } else {
                    Ok(RawElf::Dylib(self.load_dylib_impl(object)?))
                }
            }
            _ => Ok(RawElf::Exec(self.load_exec_impl(object)?)),
        }
    }
}
