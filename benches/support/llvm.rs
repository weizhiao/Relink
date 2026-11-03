//! LLVM's C API: optimize real simdjson IR and emit a native object in memory.
use crate::symbols::Symbols;
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    marker::PhantomData,
    path::PathBuf,
    process::Command,
    ptr,
};

type Handle = *mut c_void;

pub fn library_path() -> PathBuf {
    if let Some(path) = std::env::var_os("LLVM_LIBRARY") {
        return std::fs::canonicalize(path).expect("cannot resolve LLVM_LIBRARY");
    }
    let output = Command::new("llvm-config")
        .args(["--link-shared", "--libfiles"])
        .output()
        .expect("the LLVM benchmark requires llvm-config on PATH or LLVM_LIBRARY");
    assert!(output.status.success(), "llvm-config --libfiles failed");
    let paths = String::from_utf8(output.stdout).unwrap();
    let mut paths = paths.split_whitespace();
    let path = paths
        .next()
        .expect("llvm-config returned no shared library");
    assert!(
        paths.next().is_none(),
        "LLVM benchmark requires monolithic libLLVM"
    );
    std::fs::canonicalize(path).expect("cannot resolve libLLVM")
}

pub fn input_path() -> PathBuf {
    let path = std::env::var_os("LLVM_INPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/thp-input/simdjson.bc")
        });
    std::fs::canonicalize(path).expect("prepare simdjson bitcode with prepare.py llvm first")
}

pub struct Llvm<'lib> {
    context: Handle,
    original: Handle,
    machine: Handle,
    options: Handle,
    clone_module: unsafe extern "C" fn(Handle) -> Handle,
    run_passes: unsafe extern "C" fn(Handle, *const c_char, Handle, Handle) -> Handle,
    emit: unsafe extern "C" fn(Handle, Handle, c_int, *mut *mut c_char, *mut Handle) -> c_int,
    verify: unsafe extern "C" fn(Handle, c_int, *mut *mut c_char) -> c_int,
    buffer_start: unsafe extern "C" fn(Handle) -> *const c_char,
    buffer_size: unsafe extern "C" fn(Handle) -> usize,
    error_message: unsafe extern "C" fn(Handle) -> *mut c_char,
    dispose_error: unsafe extern "C" fn(*mut c_char),
    dispose_message: unsafe extern "C" fn(*mut c_char),
    dispose_buffer: unsafe extern "C" fn(Handle),
    dispose_module: unsafe extern "C" fn(Handle),
    dispose_machine: unsafe extern "C" fn(Handle),
    dispose_options: unsafe extern "C" fn(Handle),
    dispose_context: unsafe extern "C" fn(Handle),
    _library: PhantomData<&'lib ()>,
}

impl<'lib> Llvm<'lib> {
    pub fn new(library: &'lib (impl Symbols + ?Sized)) -> Self {
        // SAFETY: all declarations match llvm-c headers. All handles and code
        // pointers remain within the lifetime of this one library instance.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            let target = "X86";
            #[cfg(target_arch = "aarch64")]
            let target = "AArch64";
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            let target: &str = panic!("LLVM workload supports x86_64 and aarch64");
            for suffix in [
                "TargetInfo",
                "Target",
                "TargetMC",
                "AsmPrinter",
                "AsmParser",
            ] {
                let name = CString::new(format!("LLVMInitialize{target}{suffix}")).unwrap();
                let initialize: unsafe extern "C" fn() = library.symbol(&name);
                initialize();
            }
            let create_context: unsafe extern "C" fn() -> Handle =
                library.symbol(c"LLVMContextCreate");
            let create_buffer: unsafe extern "C" fn(*const c_char, usize, *const c_char) -> Handle =
                library.symbol(c"LLVMCreateMemoryBufferWithMemoryRangeCopy");
            let parse: unsafe extern "C" fn(Handle, Handle, *mut Handle) -> c_int =
                library.symbol(c"LLVMParseBitcodeInContext2");
            let get_triple: unsafe extern "C" fn(Handle) -> *const c_char =
                library.symbol(c"LLVMGetTarget");
            let get_target: unsafe extern "C" fn(
                *const c_char,
                *mut Handle,
                *mut *mut c_char,
            ) -> c_int = library.symbol(c"LLVMGetTargetFromTriple");
            let create_machine: unsafe extern "C" fn(
                Handle,
                *const c_char,
                *const c_char,
                *const c_char,
                c_int,
                c_int,
                c_int,
            ) -> Handle = library.symbol(c"LLVMCreateTargetMachine");
            let create_options: unsafe extern "C" fn() -> Handle =
                library.symbol(c"LLVMCreatePassBuilderOptions");
            let dispose_buffer: unsafe extern "C" fn(Handle) =
                library.symbol(c"LLVMDisposeMemoryBuffer");
            let context = create_context();
            let input = std::fs::read(input_path()).expect("cannot read LLVM input");
            let buffer = create_buffer(input.as_ptr().cast(), input.len(), c"simdjson.bc".as_ptr());
            let mut original = ptr::null_mut();
            let status = parse(context, buffer, &mut original);
            dispose_buffer(buffer);
            assert_eq!(
                status, 0,
                "cannot parse bitcode; use matching Clang/libLLVM versions"
            );
            let triple = get_triple(original);
            let mut target = ptr::null_mut();
            let mut error = ptr::null_mut();
            assert_eq!(
                get_target(triple, &mut target, &mut error),
                0,
                "LLVM target lookup failed"
            );
            // Aggressive code generation, PIC, default code model. Input target
            // attributes and triple are frozen with the bitcode, never host-tuned.
            let machine =
                create_machine(target, triple, c"generic".as_ptr(), c"".as_ptr(), 3, 2, 0);
            assert!(!machine.is_null());
            let llvm = Self {
                context,
                original,
                machine,
                options: create_options(),
                clone_module: library.symbol(c"LLVMCloneModule"),
                run_passes: library.symbol(c"LLVMRunPasses"),
                emit: library.symbol(c"LLVMTargetMachineEmitToMemoryBuffer"),
                verify: library.symbol(c"LLVMVerifyModule"),
                buffer_start: library.symbol(c"LLVMGetBufferStart"),
                buffer_size: library.symbol(c"LLVMGetBufferSize"),
                error_message: library.symbol(c"LLVMGetErrorMessage"),
                dispose_error: library.symbol(c"LLVMDisposeErrorMessage"),
                dispose_message: library.symbol(c"LLVMDisposeMessage"),
                dispose_buffer,
                dispose_module: library.symbol(c"LLVMDisposeModule"),
                dispose_machine: library.symbol(c"LLVMDisposeTargetMachine"),
                dispose_options: library.symbol(c"LLVMDisposePassBuilderOptions"),
                dispose_context: library.symbol(c"LLVMContextDispose"),
                _library: PhantomData,
            };
            llvm.verify_module(original);
            llvm
        }
    }

    pub fn anchor(&self) -> usize {
        self.run_passes as usize
    }

    pub fn prepare(&self) -> Compilation<'_> {
        Compilation {
            llvm: self,
            module: unsafe { (self.clone_module)(self.original) },
            object: ptr::null_mut(),
        }
    }

    fn check(&self, status: c_int, error: *mut c_char) {
        let message = if error.is_null() {
            String::new()
        } else {
            let message = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { (self.dispose_message)(error) };
            message
        };
        assert_eq!(status, 0, "LLVM failed: {message}");
    }

    fn verify_module(&self, module: Handle) {
        let mut error = ptr::null_mut();
        // LLVMReturnStatusAction = 2; report invalid IR without aborting.
        let status = unsafe { (self.verify)(module, 2, &mut error) };
        self.check(status, error);
    }
}

impl Drop for Llvm<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.dispose_options)(self.options);
            (self.dispose_machine)(self.machine);
            (self.dispose_module)(self.original);
            (self.dispose_context)(self.context);
        }
    }
}

pub struct Compilation<'a> {
    llvm: &'a Llvm<'a>,
    module: Handle,
    object: Handle,
}

impl Compilation<'_> {
    pub fn run(&mut self) {
        assert!(self.object.is_null(), "each compilation must use fresh IR");
        unsafe {
            let error = (self.llvm.run_passes)(
                self.module,
                c"default<O3>".as_ptr(),
                self.llvm.machine,
                self.llvm.options,
            );
            if !error.is_null() {
                let message = (self.llvm.error_message)(error);
                let text = CStr::from_ptr(message).to_string_lossy().into_owned();
                (self.llvm.dispose_error)(message);
                panic!("LLVM optimization failed: {text}");
            }
            let mut error = ptr::null_mut();
            // LLVMObjectFile = 1; output remains in memory, with no disk writes.
            let status = (self.llvm.emit)(
                self.llvm.machine,
                self.module,
                1,
                &mut error,
                &mut self.object,
            );
            self.llvm.check(status, error);
        }
    }

    pub fn fingerprint(&self) -> String {
        self.llvm.verify_module(self.module);
        assert!(!self.object.is_null());
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (self.llvm.buffer_start)(self.object).cast::<u8>(),
                (self.llvm.buffer_size)(self.object),
            )
        };
        assert!(
            bytes.starts_with(b"\x7fELF"),
            "LLVM did not emit an ELF object"
        );
        let hash = bytes.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
        format!("object_bytes={}\tobject_fnv1a64={hash:016x}", bytes.len())
    }
}

impl Drop for Compilation<'_> {
    fn drop(&mut self) {
        unsafe {
            if !self.object.is_null() {
                (self.llvm.dispose_buffer)(self.object);
            }
            (self.llvm.dispose_module)(self.module);
        }
    }
}
