#[cfg(not(windows))]
mod fixture;
#[cfg(not(windows))]
#[path = "../fixture_build/mod.rs"]
mod fixture_build;
#[cfg(not(windows))]
mod loading;

#[cfg(any(
    windows,
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
mod relocation;
#[cfg(any(
    windows,
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
mod support;
#[cfg(any(
    windows,
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
mod thread;
