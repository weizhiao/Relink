//! Explicit linking and dependency-resolution primitives.
//!
//! This module provides building blocks for callers that want to resolve
//! `DT_NEEDED` edges without hard-coding a process-global loader policy.
//! `elf_loader` stays responsible for mapping and local relocation, while
//! callers decide how dependencies are discovered and how search scopes are
//! assembled.

mod context;
mod layout;
mod linker;
mod mapped;
mod materialization;
mod plan;
mod request;
mod resolve;
mod session;
mod storage;
mod view;

pub use context::LinkContext;
pub use layout::{
    Arena, ArenaId, ArenaSharing, ArenaUsage, ClassPolicy, Materialization, MemoryClass,
    ModuleLayout, PackingPolicy, SectionAddress, SectionId, SectionMetadata, SectionPlacement,
};
pub use linker::Linker;
pub use plan::{
    AnyPass, DataAccess, DataPass, LinkPass, LinkPassPlan, LinkPipeline, ModuleId, PassScope,
    PassScopeMode, ReorderAccess, ReorderPass,
};
pub use request::{
    DefaultRelocationPlanner, DependencyOwner, DependencyRequest, RelocationInputs,
    RelocationPlanner, RelocationRequest,
};
pub use resolve::{KeyResolver, ResolvedKey};
pub use view::DependencyGraphView;
