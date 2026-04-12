//! Explicit linking and dependency-resolution primitives.
//!
//! This module provides building blocks for callers that want to resolve
//! `DT_NEEDED` edges without hard-coding a process-global loader policy.
//! `elf_loader` stays responsible for mapping and local relocation, while
//! callers decide how dependencies are discovered and how search scopes are
//! assembled.

mod api;
mod context;
mod layout;
mod plan;
mod request;
mod resolve;
mod runtime;
mod session;
mod storage;
mod view;

pub use api::{KeyResolver, RelocationInputs, RelocationPlanner, ResolvedKey};
pub use context::LinkContext;
pub use layout::{
    LayoutAddress, LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutArenaUsage,
    LayoutClassPolicy, LayoutMemoryClass, LayoutModuleMaterialization, LayoutPackingPolicy,
    LayoutRelocationSiteRepair, LayoutRetainedRelocationRepair, LayoutSectionArena,
    LayoutSectionId, LayoutSectionKind, LayoutSectionMetadata, LayoutSectionRecord,
    LayoutSectionRepair, MemoryLayoutPlan, ModuleLayout, SectionPlacement,
};
pub use plan::{LinkModuleId, LinkPass, LinkPassPlan, LinkPassScope, LinkPipeline};
pub use request::{DependencyOwner, DependencyRequest, RelocationRequest};
pub use view::DependencyGraphView;
