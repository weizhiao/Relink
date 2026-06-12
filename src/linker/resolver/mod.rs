//! Resolver interfaces and built-in resolver helpers.

mod search_path;
mod traits;

pub use search_path::{
    CandidateContext, CandidateRequest, FileNameKey, KeyRule, PathKey, ReuseResolver,
    SearchDirProvider, SearchPathEntry, SearchPathResolver,
};
pub use traits::{KeyResolver, ResolvedKey};
