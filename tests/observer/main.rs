#![cfg(not(windows))]

mod fixture;
#[path = "../fixture_build/mod.rs"]
mod fixture_build;

mod load;
#[cfg(all(feature = "object", target_arch = "x86_64"))]
mod object;
mod relocation;
