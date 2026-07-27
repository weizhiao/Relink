#[cfg(not(windows))]
mod dynamic;
mod errors;
#[path = "../fixture_build/mod.rs"]
mod fixture_build;
mod fixtures;
#[cfg(all(feature = "object", target_arch = "x86_64"))]
mod object;
#[cfg(all(feature = "object", target_arch = "riscv64"))]
mod riscv64;

#[cfg(all(feature = "object", target_arch = "x86_64"))]
pub(crate) const LOCAL_VAR_NAME: &str = "local_var";
