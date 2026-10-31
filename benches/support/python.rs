//! Shared CPython workloads for Relink and glibc.
use elf_loader::image::Module;
use libloading::os::unix::Library;
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    marker::PhantomData,
    path::PathBuf,
    process::Command,
};

type Object = *mut c_void;

pub trait Symbols {
    /// # Safety
    /// `T` must match the named symbol's C ABI type.
    unsafe fn symbol<T: Copy>(&self, name: &CStr) -> T;
}

impl Symbols for dyn Module {
    unsafe fn symbol<T: Copy>(&self, name: &CStr) -> T {
        *unsafe { self.get::<T>(name.to_bytes()) }.unwrap().unwrap()
    }
}

impl Symbols for Library {
    unsafe fn symbol<T: Copy>(&self, name: &CStr) -> T {
        *unsafe { self.get::<T>(name.to_bytes_with_nul()) }.unwrap()
    }
}

pub struct Installation {
    pub library: PathBuf,
    home: Vec<libc::wchar_t>,
    executable: Vec<libc::wchar_t>,
}

impl Installation {
    pub fn discover() -> Self {
        let output = Command::new("python3")
            .args(["-I", "-S", "-c", "import os, sys, sysconfig; print(os.path.join(sysconfig.get_config_var('LIBDIR'), sysconfig.get_config_var('INSTSONAME') or sysconfig.get_config_var('LDLIBRARY'))); print(sys.base_prefix); print(sys.executable)"])
            .output()
            .expect("cannot query Python installation");
        assert!(
            output.status.success(),
            "Python discovery failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout).unwrap();
        let mut lines = output.lines();
        let library = std::fs::canonicalize(lines.next().unwrap())
            .expect("Python's shared library is missing; install its libpython package");
        let wide = |text: &str| {
            text.chars()
                .map(|ch| ch as libc::wchar_t)
                .chain([0])
                .collect()
        };
        Self {
            library,
            home: wide(lines.next().unwrap()),
            executable: wide(lines.next().unwrap()),
        }
    }
}

pub struct Python<'a> {
    finalize: unsafe extern "C" fn() -> c_int,
    call: unsafe extern "C" fn(Object) -> Object,
    as_integer: unsafe extern "C" fn(Object) -> u64,
    decref: unsafe extern "C" fn(Object),
    print_error: unsafe extern "C" fn(),
    get_item: unsafe extern "C" fn(Object, *const c_char) -> Object,
    globals: Object,
    _owner: PhantomData<&'a ()>,
}

impl<'a> Python<'a> {
    pub fn new(library: &'a (impl Symbols + ?Sized), installation: &'a Installation) -> Self {
        // SAFETY: these are the documented CPython C ABI signatures. The loaded
        // module and the wide configuration strings outlive the interpreter.
        unsafe {
            let set_home: unsafe extern "C" fn(*const libc::wchar_t) =
                library.symbol(c"Py_SetPythonHome");
            let set_program: unsafe extern "C" fn(*const libc::wchar_t) =
                library.symbol(c"Py_SetProgramName");
            let initialize: unsafe extern "C" fn(c_int) = library.symbol(c"Py_InitializeEx");
            let run: unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int =
                library.symbol(c"PyRun_SimpleStringFlags");
            let add_module: unsafe extern "C" fn(*const c_char) -> Object =
                library.symbol(c"PyImport_AddModule");
            let get_dict: unsafe extern "C" fn(Object) -> Object =
                library.symbol(c"PyModule_GetDict");
            let version: unsafe extern "C" fn() -> *const c_char = library.symbol(c"Py_GetVersion");
            eprintln!(
                "python_version\t{}",
                CStr::from_ptr(version()).to_string_lossy()
            );
            // Avoid site customizations and third-party packages in the embedded runtime.
            let no_site: *mut c_int = library.symbol(c"Py_NoSiteFlag");
            *no_site = 1;
            set_home(installation.home.as_ptr());
            set_program(installation.executable.as_ptr());
            initialize(0);
            let mut python = Self {
                finalize: library.symbol(c"Py_FinalizeEx"),
                call: library.symbol(c"PyObject_CallNoArgs"),
                as_integer: library.symbol(c"PyLong_AsUnsignedLongLong"),
                decref: library.symbol(c"Py_DecRef"),
                print_error: library.symbol(c"PyErr_Print"),
                get_item: library.symbol(c"PyDict_GetItemString"),
                globals: std::ptr::null_mut(),
                _owner: PhantomData,
            };
            let script = CString::new(include_str!("../workloads/python.py")).unwrap();
            assert_eq!(
                run(script.as_ptr(), std::ptr::null_mut()),
                0,
                "Python workload setup failed"
            );
            let main = add_module(c"__main__".as_ptr());
            assert!(!main.is_null());
            python.globals = get_dict(main);
            assert!(!python.globals.is_null());
            python
        }
    }

    pub fn function(&self, name: &CStr) -> Object {
        let function = unsafe { (self.get_item)(self.globals, name.as_ptr()) };
        assert!(!function.is_null(), "missing Python workload {name:?}");
        function
    }

    pub fn run(&self, function: Object) -> u64 {
        // SAFETY: the callable is borrowed from __main__ while this interpreter
        // is live, and all calls stay on the initializing thread with its GIL.
        unsafe {
            let result = (self.call)(function);
            if result.is_null() {
                (self.print_error)();
                panic!("Python workload failed");
            }
            let value = (self.as_integer)(result);
            (self.decref)(result);
            value
        }
    }
}

impl Drop for Python<'_> {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { (self.finalize)() },
            0,
            "Python finalization failed"
        );
    }
}
