//! Metadata-only dynamic-library descriptions used before mapping.

use crate::elf::{ElfHeader, ElfPhdr, ElfProgramType};
use alloc::{boxed::Box, string::String};
use core::fmt;

/// Dynamic-library metadata collected before the object is mapped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScannedDynamicInfo {
    bind_now: bool,
    static_tls: bool,
}

impl ScannedDynamicInfo {
    #[inline]
    pub(crate) const fn new(bind_now: bool, static_tls: bool) -> Self {
        Self {
            bind_now,
            static_tls,
        }
    }

    /// Returns whether the object requests eager binding.
    #[inline]
    pub fn bind_now(&self) -> bool {
        self.bind_now
    }

    /// Returns whether the object requests static TLS.
    #[inline]
    pub fn static_tls(&self) -> bool {
        self.static_tls
    }
}

/// A dynamic library that has been parsed but not yet mapped into memory.
pub struct ScannedDylib<D = ()>
where
    D: 'static,
{
    name: String,
    ehdr: ElfHeader,
    phdrs: Box<[ElfPhdr]>,
    interp: Option<Box<str>>,
    rpath: Option<Box<str>>,
    runpath: Option<Box<str>>,
    needed_libs: Box<[String]>,
    dynamic: ScannedDynamicInfo,
    user_data: D,
}

impl<D> fmt::Debug for ScannedDylib<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedDylib")
            .field("name", &self.name)
            .field("needed_libs", &self.needed_libs)
            .field("bind_now", &self.dynamic.bind_now)
            .field("static_tls", &self.dynamic.static_tls)
            .finish()
    }
}

impl<D> ScannedDylib<D> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        name: String,
        ehdr: ElfHeader,
        phdrs: Box<[ElfPhdr]>,
        interp: Option<Box<str>>,
        rpath: Option<Box<str>>,
        runpath: Option<Box<str>>,
        needed_libs: Box<[String]>,
        dynamic: ScannedDynamicInfo,
        user_data: D,
    ) -> Self {
        Self {
            name,
            ehdr,
            phdrs,
            interp,
            rpath,
            runpath,
            needed_libs,
            dynamic,
            user_data,
        }
    }

    /// Returns the file name or path selected for this library.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the short library name.
    #[inline]
    pub fn short_name(&self) -> &str {
        let name = self.name();
        name.rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or(name)
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub fn ehdr(&self) -> &ElfHeader {
        &self.ehdr
    }

    /// Returns the parsed program headers.
    #[inline]
    pub fn phdrs(&self) -> &[ElfPhdr] {
        &self.phdrs
    }

    /// Returns an iterator over file-backed load segments.
    #[inline]
    pub fn load_segments(&self) -> impl Iterator<Item = &ElfPhdr> {
        self.phdrs
            .iter()
            .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
    }

    /// Returns the PT_INTERP string when present.
    #[inline]
    pub fn interp(&self) -> Option<&str> {
        self.interp.as_deref()
    }

    /// Returns the DT_RPATH string when present.
    #[inline]
    pub fn rpath(&self) -> Option<&str> {
        self.rpath.as_deref()
    }

    /// Returns the DT_RUNPATH string when present.
    #[inline]
    pub fn runpath(&self) -> Option<&str> {
        self.runpath.as_deref()
    }

    /// Returns the DT_NEEDED entries.
    #[inline]
    pub fn needed_libs(&self) -> &[String] {
        &self.needed_libs
    }

    /// Returns the dynamic binding and TLS policy flags discovered during scan.
    #[inline]
    pub fn dynamic(&self) -> &ScannedDynamicInfo {
        &self.dynamic
    }

    /// Returns a reference to the user data associated with this scan result.
    #[inline]
    pub fn user_data(&self) -> &D {
        &self.user_data
    }

    /// Returns a mutable reference to the user data associated with this scan result.
    #[inline]
    pub fn user_data_mut(&mut self) -> &mut D {
        &mut self.user_data
    }
}
