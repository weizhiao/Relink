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
mod layout;
mod linker;
mod mapped;
mod materialization;
mod passes;
mod plan;
mod request;
mod resolve;
mod resolver;
mod session;
mod storage;

pub use context::LinkContext;
pub(in crate::linker) use layout::SectionId;
pub use layout::{
    ArenaDescriptor, ArenaId, ArenaSharing, ArenaUsage, ClassPolicy, DataAccess, Materialization,
    MemoryClass, ModuleLayout, PackingPolicy, SectionAddress, SectionDataAccessRef,
    SectionMetadata, SectionPlacement,
};
pub use linker::{Linker, LoadResult};
pub(crate) use mapped::GotPltTarget;
pub use passes::{
    AnyPass, Arena, DataPass, LinkPass, LinkPassPlan, LinkPipeline, Module, PassScope,
    PassScopeMode, ReorderAccess, ReorderPass, Section, SectionDataAccess,
};
pub use request::{
    DefaultRelocationPlanner, DependencyOwner, DependencyRequest, LoadObserver, RelocationInputs,
    RelocationPlanner, RelocationRequest, RootRequest, StagedDynamic, VisibleModules,
};
pub use resolver::{
    CandidateRequest, KeyResolver, ResolvedKey, SearchDirProvider, SearchDirSource,
    SearchPathResolver,
};
pub use storage::KeyId;
