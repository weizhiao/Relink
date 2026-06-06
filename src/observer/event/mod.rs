mod lifecycle;
mod load;
mod relocation;
mod resolve;

#[cfg(feature = "object")]
pub use crate::object::layout::{SectionGroup, SectionLifetime};
pub use lifecycle::{LifecycleEvent, LifecyclePhase};
#[cfg(feature = "object")]
pub use load::SectionLayoutEvent;
pub use load::{DynamicLoadedEvent, ObjectMetadataEvent, ProgramHeaderEvent, StagedDynamic};
pub use relocation::{
    DtDebugEntry, IfuncBindingEvent, LinkActivity, ModuleRelocatedEvent, SymbolBindingEvent,
    TlsDescBindingEvent, TlsDescBindingRequest, TlsDescBindingValue,
};
pub use resolve::{ResolveDependencyEvent, ResolveRootEvent};

pub(crate) use lifecycle::{Finalizer, default_lifecycle_executor};
