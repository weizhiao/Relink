cfg_if::cfg_if! {
    if #[cfg(windows)] {
        mod windows;

        pub use windows::DefaultMmap;
        #[cfg(feature = "tls")]
        pub(crate) use windows::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use windows::{RawFile, virtual_free};
    } else if #[cfg(feature = "use-syscall")] {
        mod linux_syscall;

        pub use linux_syscall::DefaultMmap;
        #[cfg(feature = "tls")]
        pub(crate) use linux_syscall::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use linux_syscall::RawFile;
    } else if #[cfg(all(any(target_os = "linux", target_os = "android"), feature = "libc"))] {
        mod linux_libc;

        pub use linux_libc::DefaultMmap;
        #[cfg(feature = "tls")]
        pub(crate) use linux_libc::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use linux_libc::RawFile;
    } else {
        mod baremetal;

        pub use baremetal::DefaultMmap;
        #[cfg(feature = "tls")]
        pub(crate) use baremetal::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use baremetal::RawFile;
    }
}
