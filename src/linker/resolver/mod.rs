//! Resolver interfaces and built-in resolver helpers.

mod request;
mod search_path;
mod traits;

pub use request::{DependencyOwner, DependencyRequest, RootRequest, SearchOwner};
pub use search_path::{
    CandidateContext, CandidateRequest, FileNameKey, KeyRule, PathKey, SearchDirProvider,
    SearchPathEntry, SearchPathResolver,
};
pub use traits::{KeyResolver, ResolvedKey};
