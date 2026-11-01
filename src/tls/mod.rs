//! TLS registration and per-thread storage.
//!
//! Use [`DefaultTlsResolver`] for native execution, or implement [`TlsResolver`]
//! for a custom runtime. [`TlsProvider`] supplies storage, including existing host TLS.
//!
//! [`TlsRegistration`] owns a registry entry and unregisters it on drop.
//! [`TlsModule`] is borrowed metadata; [`TlsTemplate`] owns initialization bytes
//! independently of the ELF image.
//!
//! Default managed dynamic TLS requires `std`.
//! Other environments must supply a [`TlsResolver`] with their own thread lifecycle.
//! Static TLS and custom providers do not require the default thread storage.
//! On Linux/Android, managed blocks are reclaimed in the second pthread destructor
//! round; accessing managed TLS after that reclamation is unsupported.
//!
//! Recursive creation of managed dynamic TLS from allocator callbacks is not
//! supported. Existing DTV updates temporarily make managed queries unavailable
//! (`None` or an error); ELF TLS access cannot report this failure and must not
//! be used from such callbacks.
//!
//! [`DefaultTlsResolver::get_ptr_if_allocated`] does not allocate a TLS block.
//! With `std`, the lookup may initialize standard-library thread-local caches.
//! Returned pointers are valid only for the corresponding thread and module lifetime.

mod defs;
mod dtv;
mod manager;
mod module;
mod registry;
mod relocation;
mod traits;

pub(crate) use defs::TLS_GET_ADDR_SYMBOL;
pub(crate) use module::ImageTlsState;

pub use defs::{
    TlsBinding, TlsDescBinding, TlsDescRequest, TlsDescSetup, TlsIndex, TlsInfo, TlsModuleId,
    TlsRequest, TlsTemplate, TlsTpOffset,
};
pub use dtv::ThreadDtv;
pub use manager::DefaultTlsResolver;
pub use module::{TlsModule, TlsRegistration};
pub use registry::{TlsContext, TlsOwner, TlsRegistry, TlsRegistryEntry};
pub(crate) use relocation::TlsRelocOutcome;
pub use traits::{TlsProvider, TlsResolver};
