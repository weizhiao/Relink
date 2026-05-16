//! Explicit linking and dependency-resolution primitives.
//!
//! This module provides building blocks for callers that want to resolve
//! `DT_NEEDED` edges without hard-coding a process-global loader policy.
//! `elf_loader` stays responsible for mapping and local relocation, while
//! callers decide how dependencies are discovered and how search scopes are
//! assembled. Use [`SearchPathResolver`] for the common filesystem-backed case,
//! or implement [`KeyResolver`] when dependencies come from custom registries,
//! memory blobs, package stores, or host-specific search rules.

mod context;
mod linker;
mod request;
mod resolve;
mod resolver;
pub mod scan;
mod session;
mod storage;

pub use context::LinkContext;
pub use linker::{Linker, LoadResult};
pub use request::{
    DefaultRelocationPlanner, DependencyOwner, DependencyRequest, LoadObserver, RelocationInputs,
    RelocationPlanner, RelocationRequest, RootRequest, StagedDynamic, VisibleModules,
};
pub use resolver::{
    CandidateRequest, KeyResolver, ResolvedKey, SearchDirProvider, SearchDirSource,
    SearchPathResolver,
};
pub use storage::KeyId;
