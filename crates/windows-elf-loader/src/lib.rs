//! Convenience wrapper for loading ELF shared libraries on Windows.
//!
//! This crate configures Relink's default Windows mapping backend and native
//! TLS resolver. It returns an unrelocated [`RawDylib`] so callers can choose
//! the symbol scope and relocation policy. The default resolver cannot register
//! TLS on Windows; libraries requiring TLS need a custom resolver through
//! Relink's [`Loader`] and [`Domain`] APIs.
#![warn(missing_docs)]

use elf_loader::{AddressSpaceId, Domain};
use elf_loader::{
    Error, Loader,
    arch::NativeArch,
    image::RawDylib,
    input::{ElfBinary, ElfFile, ElfReader},
    memory::HostRegion,
    tls::DefaultTlsResolver,
};

type ElfDylib<D = ()> = RawDylib<D, NativeArch, HostRegion, DefaultTlsResolver>;

/// Reusable Windows configuration for mapping ELF shared libraries.
pub struct WinElfLoader {
    loader: Loader,
}

impl WinElfLoader {
    /// Creates a loader using Relink's default mapper and TLS resolver.
    pub fn new() -> Self {
        let loader = Loader::new();
        Self { loader }
    }

    /// Loads a named ELF shared library from an in-memory byte buffer.
    ///
    /// `name` is used for diagnostics and ELF search metadata; it does not
    /// cause filesystem access.
    pub fn load_dylib(
        &mut self,
        name: &str,
        bytes: impl AsRef<[u8]>,
    ) -> Result<ElfDylib<()>, Error> {
        let object = ElfBinary::new(name, bytes.as_ref());
        self.load_reader(object)
    }

    /// Opens and loads an ELF shared library from `name`.
    pub fn load_file(&mut self, name: &str) -> Result<ElfDylib<()>, Error> {
        let object = ElfFile::from_path(name)?;
        self.load_reader(object)
    }

    fn load_reader(&self, object: impl ElfReader) -> Result<ElfDylib<()>, Error> {
        self.loader
            .run(Domain::native(AddressSpaceId::PROCESS).with_tls(DefaultTlsResolver::new())?)
            .load_dylib(object)
    }
}
