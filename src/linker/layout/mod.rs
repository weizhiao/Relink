//! Physical layout planning for pre-mapping link graphs.
//!
//! This module keeps the logical module graph separate from the physical
//! section-placement plan. The layout pipeline itself is split by concern:
//! arena policy, section metadata/data, and derived placement/repair state.

mod arena;
mod plan;
mod section;

pub use arena::{
    Arena, ArenaId, ArenaSharing, ArenaUsage, ClassPolicy, MemoryClass, PackingPolicy,
};
pub use plan::Materialization;
pub use section::{ModuleLayout, SectionAddress, SectionMetadata, SectionPlacement};

pub(in crate::linker) use plan::MemoryLayoutPlan;
pub(in crate::linker) use section::SectionId;
pub use section::{DataAccess, SectionDataAccessRef};
