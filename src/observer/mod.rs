//! Observer traits and event payloads for load and relocation hooks.

mod event;
mod traits;

pub use event::{
    AfterDynamicLoadEvent, BeforeLoadEvent, DynamicRelocatedEvent, HandleResult, LifecycleEvent,
    LinkerInitEvent, LinkerRelocationEvent, RelocationEvent, SymbolBindingEvent,
};
#[cfg(feature = "object")]
pub use event::{
    AfterObjectLoadEvent, BeforeObjectLoadEvent, ObjectRelocatedEvent, SectionGroup, SectionGroups,
    SectionLayoutEvent, SectionLifetime,
};
pub(crate) use event::{LifecycleHandlers, LifecycleRunner};
pub use traits::{LinkerObserver, LoadObserver, RelocationObserver};
