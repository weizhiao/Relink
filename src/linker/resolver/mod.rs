//! Resolver interfaces and built-in resolver policies.

mod search_path;
mod traits;

pub use search_path::{CandidateRequest, SearchDirProvider, SearchDirSource, SearchPathResolver};
pub use traits::{KeyResolver, ResolvedKey};
