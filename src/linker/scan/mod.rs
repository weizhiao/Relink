//! Scan-first planning, layout, and materialization support.

pub(in crate::linker) mod layout;
pub(in crate::linker) mod mapped;
pub(in crate::linker) mod materialization;
pub(in crate::linker) mod passes;
pub(in crate::linker) mod plan;

pub use layout::{
    ArenaDescriptor, ArenaId, ArenaSharing, ArenaUsage, ClassPolicy, DataAccess, Materialization,
    MemoryClass, ModuleLayout, PackingPolicy, SectionAddress, SectionDataAccessRef,
    SectionMetadata, SectionPlacement,
};
pub use passes::{
    AnyPass, Arena, DataPass, LinkPass, LinkPassPlan, LinkPipeline, Module, PassScope,
    PassScopeMode, ReorderAccess, ReorderPass, Section, SectionDataAccess,
};

pub(in crate::linker) use layout::{MemoryLayoutPlan, SectionId};
pub(in crate::linker) use mapped::MappedRuntimeMemory;
pub(crate) use mapped::{GotPltTarget, build_arena_raw_dynamic};
pub(in crate::linker) use materialization::normalize_plan;
pub(in crate::linker) use plan::{LinkPlan, ModuleId};
