//! Import libraries managed by the Linux/glibc loader into a Relink scope.
//!
//! Available with `std` on Linux GNU targets. Imports
//! retain the native handle and expose global/weak function, object and TLS
//! exports, including GNU symbol versions. IFUNCs are resolved by glibc.
//! Libraries are opened locally and are never added to a Relink scope implicitly.
//!
//! ```no_run
//! use elf_loader::{AddressSpaceId, Domain, Result, host};
//! use elf_loader::tls::DefaultTlsResolver;
//!
//! # fn main() -> Result<()> {
//! let domain = Domain::native(AddressSpaceId::PROCESS)
//!     .with_tls(DefaultTlsResolver::new())?;
//! let module = unsafe { host::open(&domain, "/path/to/libhost.so", "libhost.so")? };
//! // Pass `module` to RelocatorRun::with_modules or insert it in a LinkContext.
//! # Ok(())
//! # }
//! ```

mod error;
mod import;
mod native;
mod tls;

pub use error::HostError;
pub use import::{main_search, open};
