#![cfg(any(
    windows,
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]

mod binding;
mod errors;
mod fixture;
#[path = "../fixture_build/mod.rs"]
mod fixture_build;
mod scope;
mod support;
