//! Thread Local Storage (TLS) support.

mod defs;
mod manager;
mod traits;

pub(crate) use defs::TlsDescDynamicArg;

pub use defs::{TlsIndex, TlsInfo};
pub use manager::DefaultTlsResolver;
pub use traits::TlsResolver;
