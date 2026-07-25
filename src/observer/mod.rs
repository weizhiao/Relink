//! Observer traits and event payloads for load and relocation hooks.

mod event;
mod traits;

pub use crate::relocation::HandleResult;
pub(crate) use event::LifecycleRunner;
pub use event::{
    AfterDynamicLoadEvent, BeforeLoadEvent, DynamicRelocatedEvent, LifecycleEvent,
    LifecycleHandlers, LinkerInitEvent, LinkerRelocationEvent, RelocationEvent, SymbolBindingEvent,
};
#[cfg(feature = "object")]
pub use event::{
    AfterObjectLoadEvent, BeforeObjectLoadEvent, ObjectRelocatedEvent, SectionGroup, SectionGroups,
    SectionLayoutEvent, SectionLifetime,
};
pub use traits::{LinkerObserver, LoadObserver, RelocationObserver, VisibleModule};
