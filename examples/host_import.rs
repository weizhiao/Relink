#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use elf_loader::{
        AddressSpaceId, Domain, LinkContext, Linker, Loader, host,
        input::{ElfFile, PathBuf},
        linker::{GraphModule, LdCache, SearchConfig, SearchPathResolver},
        tls::DefaultTlsResolver,
    };
    use std::ffi::{CStr, c_char};

    fn library_path(cache: &LdCache, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let loader = Loader::new();
        cache
            .candidates(name)
            .find(|path| {
                ElfFile::from_path(path)
                    .and_then(|file| loader.read_ehdr(&file))
                    .is_ok()
            })
            .map(PathBuf::from)
            .ok_or_else(|| format!("no native {name} in /etc/ld.so.cache").into())
    }

    env_logger::init();
    let cache = LdCache::load_system()?;
    let path = match std::env::args().nth(1) {
        Some(path) => PathBuf::from(path),
        None => library_path(&cache, "libz.so.1")?,
    };
    let libc_path = library_path(&cache, "libc.so.6")?;
    let domain = Domain::native(AddressSpaceId::PROCESS).with_tls(DefaultTlsResolver::new())?;
    // SAFETY: the cache candidate matches the native target and is the installed libc.
    let libc = unsafe { host::open(&domain, libc_path, "libc.so.6") }?;
    let mut context = LinkContext::new(domain);
    context.insert_batch([GraphModule::new("libc.so.6", libc)])?;

    // Relink loads zlib and uses the imported host libc to satisfy its dependency.
    let loaded = Linker::new()
        .with_resolver(SearchPathResolver::with_config(
            SearchConfig::new().cache(cache),
        ))
        .run()
        .load(&mut context, path)?;
    let module = context.module(loaded.root())?;
    // SAFETY: zlibVersion has this C ABI and returns a static, NUL-terminated string.
    let version = unsafe {
        let function = module
            .get::<unsafe extern "C" fn() -> *const c_char>("zlibVersion")?
            .ok_or("missing zlibVersion")?;
        CStr::from_ptr(function())
    };
    println!(
        "{}: zlib {}",
        module.name().escape_ascii(),
        version.to_string_lossy()
    );
    drop(loaded.release(&mut context)?);
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn main() {
    eprintln!("This example requires Linux/glibc.");
}
