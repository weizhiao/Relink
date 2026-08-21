//! Resolver interfaces and built-in resolver helpers.

mod request;
mod search_path;
mod traits;

pub(crate) use request::{DependencySource, LoaderVisitor};
pub use request::{ResolveInput, ResolveRequest};
pub use search_path::{CandidateRequest, SearchPathResolver};
pub use traits::{KeyResolver, ResolvedKey};
