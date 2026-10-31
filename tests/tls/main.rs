#[cfg(not(windows))]
mod fixture;
#[cfg(not(windows))]
#[path = "../fixture_build/mod.rs"]
mod fixture_build;
#[cfg(not(windows))]
mod loading;

#[cfg(feature = "std")]
mod relocation;
#[cfg(feature = "std")]
mod support;
#[cfg(feature = "std")]
mod thread;

#[cfg(all(feature = "std", target_os = "linux", target_env = "gnu"))]
mod destruction;
