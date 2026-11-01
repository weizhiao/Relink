//! libclang's C API, resolved from the library under test.
use crate::symbols::Symbols;
use elf_loader::{Loader, input::ElfFile};
use std::{
    ffi::{CString, c_char, c_int, c_uint, c_void},
    marker::PhantomData,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    process::Command,
    ptr,
};

type Handle = *mut c_void;

pub fn library_path() -> PathBuf {
    let output = Command::new("llvm-config")
        .arg("--libdir")
        .output()
        .expect("the Clang benchmark requires llvm-config on PATH");
    assert!(output.status.success(), "llvm-config --libdir failed");
    let directory = String::from_utf8(output.stdout).expect("invalid LLVM library directory");
    let mut candidates: Vec<_> = std::fs::read_dir(directory.trim())
        .expect("cannot read the LLVM library directory")
        .flatten()
        .map(|entry| entry.path())
        .filter_map(|path| {
            // Accept the C API library, excluding libclang-cpp and compiler runtimes.
            let name = path.file_name()?.to_str()?.strip_prefix("libclang")?;
            let (version, suffix) = name.split_once(".so")?;
            if !suffix.is_empty() && !suffix.starts_with('.') {
                return None;
            }
            let version = if version.is_empty() {
                u32::MAX // Prefer the installation's unversioned default.
            } else {
                version.strip_prefix('-')?.parse().ok()?
            };
            Some((version, path))
        })
        .collect();
    candidates.sort_by(|a, b| b.cmp(a));
    let loader = Loader::new();
    candidates.into_iter().find_map(|(_, path)| {
        let path = std::fs::canonicalize(path).ok()?;
        let file =
            ElfFile::from_path(elf_loader::input::Path::new(path.as_os_str().as_bytes())).ok()?;
        loader.read_ehdr(&file).ok()?;
        Some(path)
    }).expect("cannot find native libclang in llvm-config --libdir; install the matching libclang shared library")
}

pub fn input_path() -> PathBuf {
    let path = std::env::var_os("SIMDJSON_INPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/thp-input/simdjson.ii")
        });
    std::fs::canonicalize(path)
        .expect("prepare simdjson.ii first (see benches/workloads/README.md)")
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Cursor {
    kind: c_uint,
    xdata: c_int,
    data: [*const c_void; 3],
}

type Visitor = unsafe extern "C" fn(Cursor, Cursor, *mut c_void) -> c_uint;

pub struct Clang<'lib> {
    index: Handle,
    file: CString,
    dispose_index: unsafe extern "C" fn(Handle),
    parse: unsafe extern "C" fn(
        Handle,
        *const c_char,
        *const *const c_char,
        c_int,
        *mut c_void,
        c_uint,
        c_uint,
        *mut Handle,
    ) -> c_int,
    dispose_unit: unsafe extern "C" fn(Handle),
    cursor: unsafe extern "C" fn(Handle) -> Cursor,
    visit: unsafe extern "C" fn(Cursor, Visitor, *mut c_void) -> c_uint,
    diagnostics: unsafe extern "C" fn(Handle) -> c_uint,
    diagnostic: unsafe extern "C" fn(Handle, c_uint) -> Handle,
    severity: unsafe extern "C" fn(Handle) -> c_uint,
    dispose_diagnostic: unsafe extern "C" fn(Handle),
    _library: PhantomData<&'lib ()>,
}

impl<'lib> Clang<'lib> {
    pub fn new(library: &'lib (impl Symbols + ?Sized)) -> Self {
        // SAFETY: signatures and Cursor layout match clang-c/Index.h. Handles
        // and function pointers remain tied to this library's lifetime.
        unsafe {
            let create: unsafe extern "C" fn(c_int, c_int) -> Handle =
                library.symbol(c"clang_createIndex");
            let index = create(0, 0);
            assert!(!index.is_null(), "Clang could not create an index");
            Self {
                index,
                file: CString::new(input_path().as_os_str().as_bytes()).unwrap(),
                dispose_index: library.symbol(c"clang_disposeIndex"),
                parse: library.symbol(c"clang_parseTranslationUnit2"),
                dispose_unit: library.symbol(c"clang_disposeTranslationUnit"),
                cursor: library.symbol(c"clang_getTranslationUnitCursor"),
                visit: library.symbol(c"clang_visitChildren"),
                diagnostics: library.symbol(c"clang_getNumDiagnostics"),
                diagnostic: library.symbol(c"clang_getDiagnostic"),
                severity: library.symbol(c"clang_getDiagnosticSeverity"),
                dispose_diagnostic: library.symbol(c"clang_disposeDiagnostic"),
                _library: PhantomData,
            }
        }
    }

    pub fn anchor(&self) -> usize {
        self.parse as usize
    }

    pub fn parse(&self) -> TranslationUnit<'_> {
        let args = [
            c"-x".as_ptr(),
            c"c++-cpp-output".as_ptr(),
            c"-std=c++17".as_ptr(),
        ];
        let mut unit = ptr::null_mut();
        // SAFETY: index, NUL-terminated paths/options, and output pointer are live.
        // No unsaved files or special TU flags; parse includes function bodies.
        let status = unsafe {
            (self.parse)(
                self.index,
                self.file.as_ptr(),
                args.as_ptr(),
                args.len() as c_int,
                ptr::null_mut(),
                0,
                0,
                &mut unit,
            )
        };
        assert_eq!(status, 0, "Clang could not parse simdjson.ii");
        assert!(!unit.is_null());
        TranslationUnit { clang: self, unit }
    }
}

impl Drop for Clang<'_> {
    fn drop(&mut self) {
        unsafe { (self.dispose_index)(self.index) };
    }
}

pub struct TranslationUnit<'a> {
    clang: &'a Clang<'a>,
    unit: Handle,
}

impl TranslationUnit<'_> {
    pub fn fingerprint(&self) -> String {
        // Hash cursor kinds in traversal order as well as counting nodes. This
        // is a structural sanity check, not proof of semantic AST equivalence.
        unsafe extern "C" fn visit(cursor: Cursor, _: Cursor, data: *mut c_void) -> c_uint {
            let state = unsafe { &mut *data.cast::<(u64, u64)>() };
            state.0 += 1;
            state.1 = (state.1 ^ u64::from(cursor.kind)).wrapping_mul(0x100000001b3);
            2 // CXChildVisit_Recurse
        }
        // SAFETY: the unit is live; diagnostics are individually released and
        // clang_visitChildren invokes the callback synchronously.
        unsafe {
            for i in 0..(self.clang.diagnostics)(self.unit) {
                let diagnostic = (self.clang.diagnostic)(self.unit, i);
                let severity = (self.clang.severity)(diagnostic);
                (self.clang.dispose_diagnostic)(diagnostic);
                assert!(
                    severity < 3,
                    "simdjson parse contains errors; use matching Clang preprocessing and libclang versions"
                );
            }
            let mut state = (0_u64, 0xcbf29ce484222325_u64);
            (self.clang.visit)(
                (self.clang.cursor)(self.unit),
                visit,
                (&mut state as *mut (u64, u64)).cast(),
            );
            assert!(state.0 > 0, "empty simdjson AST");
            format!("nodes={}\tkinds_fnv1a64={:016x}", state.0, state.1)
        }
    }
}

impl Drop for TranslationUnit<'_> {
    fn drop(&mut self) {
        unsafe { (self.clang.dispose_unit)(self.unit) };
    }
}
