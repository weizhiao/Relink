//! Physical layout planning for pre-mapping link graphs.
//!
//! This module keeps the logical module graph separate from the physical
//! section-placement plan. The layout pipeline itself is split by concern:
//! arena policy, section metadata/data, and derived placement/repair state.

mod arena;
mod plan;
mod section;

#[cfg(test)]
mod tests;

pub use arena::{
    LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutArenaUsage, LayoutClassPolicy,
    LayoutMemoryClass, LayoutPackingPolicy,
};
pub use plan::{Materialization, MemoryLayoutPlan};
pub use section::{
    LayoutAddress, LayoutSectionId, LayoutSectionMetadata, ModuleLayout, SectionPlacement,
};
