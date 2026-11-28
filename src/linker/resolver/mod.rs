//! Resolver interfaces and built-in resolver helpers.

mod ld_cache;
mod request;
mod search_path;
mod traits;

pub use ld_cache::LdCache;
pub(crate) use request::LoaderVisitor;
pub use request::{ResolveInput, ResolveRequest};
pub use search_path::{CandidateRequest, SearchConfig, SearchPathResolver};
pub(crate) use traits::ResolvedKind;
pub use traits::{KeyResolver, ResolvedDependency, ResolvedKey};
