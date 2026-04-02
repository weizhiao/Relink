//! Physical layout planning for pre-mapping link graphs.
//!
//! This module keeps the logical module graph separate from the physical
//! section-placement plan. The layout pipeline itself is split by concern:
//! arena policy, section metadata/data, address derivation, and passes.

mod address;
mod arena;
mod pass;
mod physical;
mod plan;
mod region;
mod repair;
mod section;

#[cfg(test)]
mod tests;

pub use address::{LayoutAddress, LayoutAddressMap, ModuleAddressMap, RelocationSiteAddress};
pub use arena::{
    LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutArenaUsage, LayoutClassPolicy,
    LayoutMemoryClass, LayoutPackingPolicy,
};
pub use pass::PackSectionsPass;
pub use physical::{
    LayoutArenaImage, LayoutPhysicalImage, LayoutPhysicalPlan, ModulePhysicalLayout,
    ModulePhysicalSlice,
};
pub use plan::MemoryLayoutPlan;
pub use region::{
    LayoutRegion, LayoutRegionArena, LayoutRegionId, LayoutRegionPlacement, SectionRegionPlacement,
};
pub use repair::{
    LayoutRelocationSiteRepair, LayoutRepairPlan, LayoutRepairStatus,
    LayoutRetainedRelocationRepair, LayoutSectionRepair, ModuleLayoutRepair,
};
pub use section::{
    LayoutRetainedRelocationSection, LayoutSectionData, LayoutSectionDataArena,
    LayoutSectionDataId, LayoutSectionId, LayoutSectionMetadata, LayoutSectionMetadataArena,
    LayoutSectionSource, ModuleLayout, SectionPlacement,
};
