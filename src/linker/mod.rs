//! Explicit linking and dependency-resolution primitives.
//!
//! This module provides building blocks for callers that want to resolve
//! `DT_NEEDED` edges without hard-coding a process-global loader policy.
//! `elf_loader` stays responsible for mapping and local relocation, while
//! callers decide how dependencies are discovered and how search scopes are
//! assembled.

mod api;
mod context;
mod request;
mod session;
mod storage;
mod view;

pub use api::{ModuleRelocator, ModuleResolver, ResolvedModule};
pub use context::LinkContext;
pub use request::{DependencyRequest, RelocationRequest};
pub use view::LinkContextView;
