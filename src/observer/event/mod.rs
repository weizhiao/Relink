mod lifecycle;
mod linker;
mod load;
#[cfg(feature = "object")]
mod object;
mod relocation;

#[cfg(feature = "object")]
pub use crate::object::layout::{SectionGroup, SectionGroups, SectionLifetime};
pub use lifecycle::LifecycleEvent;
pub use linker::{LinkerInitEvent, LinkerRelocationEvent};
pub use load::{AfterDynamicLoadEvent, BeforeLoadEvent};
#[cfg(feature = "object")]
pub use object::{
    AfterObjectLoadEvent, BeforeObjectLoadEvent, ObjectRelocatedEvent, SectionLayoutEvent,
};
pub use relocation::{DynamicRelocatedEvent, HandleResult, RelocationEvent, SymbolBindingEvent};

pub(crate) use lifecycle::{LifecycleHandlers, LifecycleRunner};
