pub(super) use super::read_exact_at;

cfg_if::cfg_if! {
    if #[cfg(feature = "use-syscall")] {
        mod syscall;

        pub use syscall::DefaultMmap;
        pub(crate) use syscall::{
            RawFile, current_thread_id, get_thread_local_ptr, getauxval, path_is_dir,
            register_thread_destructor,
        };
    } else {
        mod libc;

        pub use libc::DefaultMmap;
        pub(crate) use libc::{
            RawFile, current_thread_id, get_thread_local_ptr, getauxval, path_is_dir,
            register_thread_destructor,
        };
    }
}
