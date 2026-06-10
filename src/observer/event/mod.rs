mod lifecycle;
mod load;
#[cfg(feature = "object")]
mod object;
mod relocation;
mod resolve;

#[cfg(feature = "object")]
pub use crate::object::layout::{SectionGroup, SectionLifetime};
pub use lifecycle::{LifecycleEvent, LifecyclePhase};
pub use load::{DynamicLoadedEvent, ProgramHeaderEvent, StagedDynamic};
#[cfg(feature = "object")]
pub use object::{ObjectMetadataEvent, SectionLayoutEvent};
pub use relocation::{
    DtDebugEntry, IfuncBindingEvent, LinkActivity, ModuleRelocatedEvent, SymbolBindingEvent,
    TlsDescBindingEvent, TlsDescBindingRequest, TlsDescBindingValue,
};
pub use resolve::{ResolveDependencyEvent, ResolveRootEvent};

pub(crate) use lifecycle::{Finalizer, default_lifecycle_executor};
