mod lifecycle;
mod load;
#[cfg(feature = "object")]
mod object;
mod relocation;
mod resolve;

#[cfg(feature = "object")]
pub use crate::object::layout::{SectionGroup, SectionGroups, SectionLifetime};
pub use lifecycle::{FiniEvent, InitEvent};
pub use load::{AfterDynamicLoadEvent, BeforeDynamicLoadEvent, StagedDynamic};
#[cfg(feature = "object")]
pub use object::{
    AfterObjectLoadEvent, BeforeObjectLoadEvent, ObjectRelocatedEvent, SectionLayoutEvent,
};
pub use relocation::{
    DynamicRelocatedEvent, SymbolBindingEvent, TlsDescBindingEvent, TlsDescBindingRequest,
    TlsDescBindingValue,
};
pub use resolve::{ResolveDependencyEvent, ResolveRootEvent};

pub(crate) use lifecycle::Finalizer;
