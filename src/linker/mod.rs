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
mod scan;
mod session;
mod storage;
mod view;

pub use api::{KeyResolver, RelocationInputs, RelocationPlanner, ResolvedKey};
pub use context::LinkContext;
pub use layout::{
    LayoutAddress, LayoutAddressMap, LayoutArena, LayoutArenaId, LayoutArenaImage,
    LayoutArenaSharing, LayoutArenaUsage, LayoutClassPolicy, LayoutMemoryClass,
    LayoutPackingPolicy, LayoutPhysicalImage, LayoutPhysicalPlan, LayoutRegion, LayoutRegionArena,
    LayoutRegionId, LayoutRegionPlacement, LayoutRelocationSiteRepair, LayoutRepairPlan,
    LayoutRepairStatus, LayoutRetainedRelocationRepair, LayoutRetainedRelocationSection,
    LayoutSectionData, LayoutSectionDataArena, LayoutSectionDataId, LayoutSectionId,
    LayoutSectionMetadata, LayoutSectionMetadataArena, LayoutSectionRepair, LayoutSectionSource,
    MemoryLayoutPlan, ModuleAddressMap, ModuleLayout, ModuleLayoutRepair, ModulePhysicalLayout,
    ModulePhysicalSlice, PackSectionsPass, RelocationSiteAddress, SectionPlacement,
    SectionRegionPlacement,
};
pub use plan::{LinkPass, LinkPipeline, LinkPlan};
pub use request::{DependencyContext, DependencyOwner, DependencyRequest, RelocationRequest};
pub use scan::ScanContextView;
pub use view::LinkContextView;
