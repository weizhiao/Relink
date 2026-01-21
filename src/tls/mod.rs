//! Thread Local Storage (TLS) support.

mod manager;
mod traits;

pub use manager::DefaultTlsResolver;
pub use traits::TlsResolver;

pub(crate) use traits::{TlsIndex, TlsInfo};
