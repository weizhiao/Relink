//! Serial NPB conjugate gradient with large static arrays in BSS.
use crate::symbols::Symbols;
use std::{
    ffi::{c_char, c_int},
    marker::PhantomData,
    path::PathBuf,
    time::Duration,
};

pub fn library_path() -> PathBuf {
    let path = std::env::var_os("NPB_CG_LIBRARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/thp-input/npb-cg/libnpb-cg-B.so")
        });
    std::fs::canonicalize(path).expect("prepare NPB CG first (see benches/workloads/README.md)")
}

#[repr(C)]
#[derive(Default)]
struct Result {
    kernel_ns: u64,
    zeta: f64,
    verified: c_int,
    dimension: c_int,
    iterations: c_int,
    class: c_char,
}

pub struct Cg<'lib> {
    run: unsafe extern "C" fn(*mut Result),
    _library: PhantomData<&'lib ()>,
}

impl<'lib> Cg<'lib> {
    pub fn new(library: &'lib (impl Symbols + ?Sized)) -> Self {
        Self {
            // SAFETY: this ABI is defined by workloads/cg_adapter.c.
            run: unsafe { library.symbol(c"relink_cg_run") },
            _library: PhantomData,
        }
    }

    pub fn anchor(&self) -> usize {
        self.run as usize
    }

    pub fn run(&mut self) -> (Duration, String) {
        let mut result = Result::default();
        // SAFETY: exclusive access serializes the library's static workspace;
        // the result is writable and the function remains tied to the library.
        unsafe { (self.run)(&mut result) };
        assert_eq!(result.verified, 1, "NPB CG numerical verification failed");
        assert!(result.kernel_ns > 0 && result.zeta.is_finite());
        (
            Duration::from_nanos(result.kernel_ns),
            format!(
                "class={}\tdimension={}\titerations={}\tzeta={:.13e}",
                result.class as u8 as char, result.dimension, result.iterations, result.zeta
            ),
        )
    }
}
