//! Resolver interfaces and built-in resolver helpers.

mod request;
mod search_path;
mod traits;

pub use request::{DependencyRequest, RootRequest};
pub(crate) use request::{DependencySource, LoaderVisitor};
pub use search_path::{
    CandidateContext, CandidateRequest, FileNameKey, KeyMapper, PathKey, SearchPathResolver,
};
pub use traits::{KeyResolver, ResolvedKey};
