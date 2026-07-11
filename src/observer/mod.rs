//! Observer traits and event payloads for load and relocation hooks.

mod event;
mod traits;

pub(crate) use event::Finalizer;
pub use event::{
    AfterDynamicLoadEvent, BeforeLoadEvent, DynamicRelocatedEvent, FiniEvent, HandleResult,
    InitEvent, RelocationEvent, SymbolBindingEvent,
};
#[cfg(feature = "object")]
pub use event::{
    AfterObjectLoadEvent, BeforeObjectLoadEvent, ObjectRelocatedEvent, SectionGroup, SectionGroups,
    SectionLayoutEvent, SectionLifetime,
};
pub use traits::{LoadObserver, RelocationObserver};
