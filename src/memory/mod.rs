//! Virtual memory and mapped image abstractions.

mod defs;
mod host;
mod traits;

pub use defs::{MappedRegion, VmAddr, VmOffset};
pub(crate) use defs::{MappedView, align_up, rounddown, roundup};
pub use host::HostRegion;
pub use traits::{ImageMemory, ImageMemoryExt, RegionAccess};
