//! Runtime execution abstractions for mapped images.

mod native;
mod traits;

pub use native::NativeCodeExecutor;
pub use traits::{CodeContext, CodeExecutor};
