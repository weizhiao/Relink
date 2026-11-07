//! Root library lookup and the shared, explicit host-runtime boundary.
use elf_loader::{
    AddressSpaceId, Domain, LinkContext, Loader, host,
    image::ModuleHandle,
    input::{ElfFile, Path as ElfPath},
    linker::{GraphModule, LdCache, SearchPathResolver},
    tls::DefaultTlsResolver,
};
use std::{
    ffi::OsStr,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

// A fixed host boundary, independent of the selected workloads. Candidate
// headers are checked against the native target, including the loader names.
const HOST_RUNTIMES: &[&str] = &[
    "libc.so.6",
    "libm.so.6",
    "libdl.so.2",
    "libpthread.so.0",
    "librt.so.1",
    "libgcc_s.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux.so.2",
    "ld-linux-aarch64.so.1",
];

/// Shared cache snapshot for root lookup and timed dependency lookup.
pub struct LibraryCache {
    cache: LdCache,
    record_manifest: bool,
}

impl LibraryCache {
    pub fn new(record_manifest: bool) -> Self {
        let cache = Self {
            cache: LdCache::load_system().expect("cannot read /etc/ld.so.cache"),
            record_manifest,
        };
        cache.record_file("cache", "ld.so.cache", Path::new("/etc/ld.so.cache"));
        cache
    }

    /// Machine-readable records consumed by ci/bench.sh to hash the exact files.
    fn record_file(&self, kind: &str, soname: &str, path: &Path) {
        if self.record_manifest {
            eprintln!(
                "manifest\t{kind}\t{soname}\t{}",
                fs::canonicalize(path).unwrap().display()
            );
        }
    }

    /// Finds the first installed candidate accepted by the native loader backend.
    pub fn find(&self, name: &str) -> Option<PathBuf> {
        let loader = Loader::new();
        let run = loader.run(Domain::native(AddressSpaceId::PROCESS));
        self.cache.candidates(name).find_map(|path| {
            let file = ElfFile::from_path(path).ok()?;
            run.read_ehdr(&file).ok()?;
            Some(PathBuf::from(OsStr::from_bytes(path.as_bytes())))
        })
    }

    pub fn resolver(&self) -> SearchPathResolver {
        let mut resolver = SearchPathResolver::new();
        resolver.push_rpath();
        if let Some(paths) = std::env::var_os("LD_LIBRARY_PATH") {
            let executable = std::env::current_exe().expect("cannot locate benchmark executable");
            resolver.push_library_path(
                ElfPath::new(paths.as_bytes()),
                ElfPath::new(executable.parent().unwrap().as_os_str().as_bytes()),
            );
        }
        resolver.push_runpath();
        resolver.push_ld_cache(self.cache.clone());
        resolver
    }
}

/// Resolve and record the benchmark root before timing.
pub fn root_path(cache: &LibraryCache, name: &str) -> PathBuf {
    assert!(
        !HOST_RUNTIMES.contains(&name),
        "{name} is a preloaded host runtime, not a load/unload workload"
    );
    let path = cache
        .find(name)
        .unwrap_or_else(|| panic!("missing compatible {name}; see benches/README.md"));
    cache.record_file("root", name, &path);
    path
}

struct HostModule {
    soname: String,
    module: ModuleHandle,
}

impl HostModule {
    fn load(
        domain: &Domain<elf_loader::arch::NativeArch, DefaultTlsResolver>,
        soname: &str,
        path: &Path,
    ) -> Self {
        let module =
            unsafe { host::open(domain, ElfPath::new(path.as_os_str().as_bytes()), soname) }
                .unwrap();
        Self {
            soname: soname.to_owned(),
            module,
        }
    }
}

/// One shared set of native runtimes and their synthetic export tables.
pub struct HostLibraries {
    domain: Domain<elf_loader::arch::NativeArch, DefaultTlsResolver>,
    libraries: Vec<HostModule>,
}

impl HostLibraries {
    pub fn new(cache: &LibraryCache) -> Self {
        let domain = Domain::native(AddressSpaceId::PROCESS)
            .with_tls(DefaultTlsResolver::new())
            .unwrap();
        let libraries = HOST_RUNTIMES
            .iter()
            .filter_map(|soname| {
                cache.find(soname).map(|path| {
                    let module = HostModule::load(&domain, soname, &path);
                    cache.record_file("host", soname, &path);
                    module
                })
            })
            .collect();
        Self { domain, libraries }
    }

    pub fn context(&self) -> LinkContext<(), elf_loader::arch::NativeArch, DefaultTlsResolver> {
        let mut context = LinkContext::new(self.domain.clone());
        let modules = self
            .libraries
            .iter()
            .map(|host| GraphModule::new(host.soname.clone(), host.module.clone()));
        context.insert_batch(modules).unwrap();
        context
    }
}
