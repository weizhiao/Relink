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
mod driver;
mod resolve;
mod resolver;
mod run;
pub mod scan;
mod session;
mod storage;
mod unload;

pub use context::{LinkContext, LoadGroup};
pub use driver::{Linker, LoadResult};
pub use resolver::{
    CandidateContext, CandidateRequest, FileNameKey, KeyMapper, KeyResolver, PathKey, ResolveInput,
    ResolveRequest, ResolvedKey, SearchPathResolver,
};
pub use run::{FailedLoad, LinkerRun, PreparedLoad, PublishedLoad, RelocatedLoad};
pub use storage::{ContextId, KeyId, ModuleId, ModuleLease};
pub use unload::{UnloadGroup, UnloadedModule};
