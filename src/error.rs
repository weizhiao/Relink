use alloc::borrow::Cow;
use core::fmt::{Debug, Display};

/// Error types used throughout the `elf_loader` library.
/// These errors represent various failure conditions that can occur during
/// ELF file loading, parsing, and relocation operations.
#[derive(Debug)]
pub enum Error {
    /// An error occurred while opening, reading, or writing ELF files.
    ///
    /// This error typically indicates issues with file I/O operations such as:
    /// * File not found
    /// * Permission denied
    /// * I/O errors during read/write operations
    Io {
        /// A descriptive message about the I/O error.
        msg: Cow<'static, str>,
    },

    /// An error occurred during memory mapping operations.
    ///
    /// This error typically indicates issues with memory management operations such as:
    /// * Failed to map file into memory
    /// * Failed to change memory protection
    /// * Failed to unmap memory regions
    Mmap {
        /// A descriptive message about the memory mapping error.
        msg: Cow<'static, str>,
    },

    /// An error occurred during dynamic library relocation.
    ///
    /// This error typically indicates issues with symbol resolution or relocation
    /// operations such as:
    /// * Undefined symbols
    /// * Incompatible symbol types
    /// * Relocation calculation errors
    Relocation {
        /// A descriptive message about the relocation error.
        msg: Cow<'static, str>,
    },

    /// An error occurred while parsing the dynamic section.
    ///
    /// This error typically indicates issues with parsing the `.dynamic` section such as:
    /// * Invalid dynamic entry types
    /// * Missing required dynamic entries
    /// * Malformed dynamic section data
    ParseDynamic {
        /// A descriptive message about the dynamic section parsing error.
        msg: Cow<'static, str>,
    },

    /// An error occurred while parsing the ELF header.
    ///
    /// This error typically indicates issues with the ELF header such as:
    /// * Invalid magic bytes
    /// * Unsupported ELF class or data encoding
    /// * Invalid ELF header fields
    ParseEhdr {
        /// A descriptive message about the ELF header parsing error.
        msg: Cow<'static, str>,
    },

    /// An error occurred while parsing program headers.
    ///
    /// This error typically indicates issues with program header parsing such as:
    /// * Invalid program header types
    /// * Malformed program header data
    /// * Incompatible program header entries
    ParsePhdr {
        /// A descriptive message about the program header parsing error.
        msg: Cow<'static, str>,
    },

    /// An error occurred in a user-defined callback or handler.
    Custom {
        /// A descriptive message about the custom error.
        msg: Cow<'static, str>,
    },

    /// An error occurred during TLS (Thread Local Storage) processing.
    Tls {
        /// A descriptive message about the TLS error.
        msg: Cow<'static, str>,
    },
}

impl Display for Error {
    /// Formats the error for display purposes.
    ///
    /// This implementation provides human-readable error messages for all error variants.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io { msg } => write!(f, "I/O error: {msg}"),
            Error::Mmap { msg } => write!(f, "Memory mapping error: {msg}"),
            Error::Relocation { msg, .. } => write!(f, "Relocation error: {msg}"),
            Error::ParseDynamic { msg } => write!(f, "Dynamic section parsing error: {msg}"),
            Error::ParseEhdr { msg } => write!(f, "ELF header parsing error: {msg}"),
            Error::ParsePhdr { msg, .. } => write!(f, "Program header parsing error: {msg}"),
            Error::Custom { msg } => write!(f, "Custom error: {msg}"),
            Error::Tls { msg } => write!(f, "TLS error: {msg}"),
        }
    }
}

impl core::error::Error for Error {}

/// Creates an I/O error with the specified message.
///
/// This is a convenience function for creating `Error::Io` variants.
///
/// # Arguments
/// * `msg` - The error message.
///
/// # Returns
/// An `Error::Io` variant with the specified message.
#[cold]
#[inline(never)]
#[allow(unused)]
pub(crate) fn io_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Io { msg: msg.into() }
}

/// Creates a relocation error with the specified message.
///
/// This is a convenience function for creating `Error::Relocation` variants.
///
/// # Arguments
/// * `msg` - The error message.
///
/// # Returns
/// An `Error::Relocation` variant with the specified message.
#[cold]
#[inline(never)]
pub(crate) fn relocate_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Relocation { msg: msg.into() }
}

/// Creates a dynamic section parsing error with the specified message.
///
/// This is a convenience function for creating `Error::ParseDynamic` variants.
///
/// # Arguments
/// * `msg` - The error message.
///
/// # Returns
/// An `Error::ParseDynamic` variant with the specified message.
#[cold]
#[inline(never)]
pub(crate) fn parse_dynamic_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::ParseDynamic { msg: msg.into() }
}

/// Creates an ELF header parsing error with the specified message.
///
/// This is a convenience function for creating `Error::ParseEhdr` variants.
///
/// # Arguments
/// * `msg` - The error message.
///
/// # Returns
/// An `Error::ParseEhdr` variant with the specified message.
#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::ParseEhdr { msg: msg.into() }
}

/// Creates a custom error with the specified message.
///
/// This is a convenience function for creating `Error::Custom` variants.
///
/// # Arguments
/// * `msg` - The error message.
///
/// # Returns
/// An `Error::Custom` variant with the specified message.
#[cold]
#[inline(never)]
#[allow(unused)]
pub fn custom_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Custom { msg: msg.into() }
}

/// Creates a TLS error with the specified message.
///
/// This is a convenience function for creating `Error::Tls` variants.
///
/// # Arguments
/// * `msg` - The error message.
///
/// # Returns
/// An `Error::Tls` variant with the specified message.
#[cold]
#[inline(never)]
pub(crate) fn tls_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Tls { msg: msg.into() }
}
