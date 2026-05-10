//! Resolver interfaces and built-in resolver policies.

mod search_path;
mod traits;

pub use search_path::SearchPathResolver;
pub use traits::{KeyResolver, ResolvedKey};
