//! Explicit linking and dependency-resolution primitives.
//!
//! This module provides building blocks for callers that want to resolve
//! `DT_NEEDED` edges without hard-coding a process-global loader policy.
//! `elf_loader` stays responsible for mapping and local relocation, while
//! callers decide how dependencies are discovered and how search scopes are
//! assembled.

mod api;
mod context;
mod plan;
mod request;
mod scan;
mod session;
mod storage;
mod view;

pub use api::{
    MaterializationRequest, ModuleMaterializer, ModuleRelocator, ModuleResolver, ResolvedModule,
};
pub use context::LinkContext;
pub use plan::{LinkPass, LinkPipeline, LinkPlan};
pub use request::{DependencyRequest, RelocationRequest};
pub use scan::{ModuleScanner, ResolvedScan, ScanContextView, ScanRequest};
pub use view::LinkContextView;
