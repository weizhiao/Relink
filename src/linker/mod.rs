//! Loads ELF dependency graphs into a [`LinkContext`].
//!
//! Use [`SearchPathResolver`] for filesystem search, or implement [`KeyResolver`]
//! for custom dependency sources and policies.

mod address;
mod context;
mod driver;
mod import;
mod resolve;
mod resolver;
mod run;
pub mod scan;
mod session;
mod storage;
mod unload;

pub use address::{AddressIndex, AddressMatch};
pub use context::LinkContext;
pub use driver::{Linker, LoadResult};
pub use import::GraphModule;
pub use resolver::{
    CandidateRequest, KeyResolver, LdCache, ResolveInput, ResolveRequest, ResolvedDependency,
    ResolvedKey, SearchConfig, SearchPathResolver,
};
pub use run::{FailedLoad, LinkerRun, PreparedLoad, PublishedLoad, RelocatedLoad};
pub use storage::{ContextId, LeaseError, ModuleId, ModuleKey, ModuleLease};
pub use unload::{UnloadGroup, UnloadedModule};
