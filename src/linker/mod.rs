//! Explicit linking and dependency-resolution primitives.
//!
//! This module provides building blocks for callers that want to resolve
//! `DT_NEEDED` edges without hard-coding a process-global loader policy.
//! `elf_loader` stays responsible for mapping and local relocation, while
//! callers decide how dependencies are discovered and how search scopes are
//! assembled.

mod context;
mod layout;
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
    LayoutAddress, LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutArenaUsage,
    LayoutClassPolicy, LayoutMemoryClass, LayoutPackingPolicy, LayoutSectionArena, LayoutSectionId,
    LayoutSectionMetadata, LayoutSectionRecord, Materialization, MemoryLayoutPlan, ModuleLayout,
    SectionPlacement,
};
pub use plan::{LinkModuleId, LinkPass, LinkPassPlan, LinkPassScope, LinkPipeline};
pub use request::{
    DependencyOwner, DependencyRequest, RelocationInputs, RelocationPlanner, RelocationRequest,
};
pub use resolve::{KeyResolver, ResolvedKey};
pub use view::DependencyGraphView;
