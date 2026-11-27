//! Run the same application operations through Relink and the system loader.
#![cfg(all(target_os = "linux", target_env = "gnu"))]

#[path = "../benches/support/libraries.rs"]
mod libraries;
#[path = "../benches/support/symbols.rs"]
mod symbols;

use elf_loader::{Linker, image::Module, input::Path};
use libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW};
use std::{
    ffi::{c_char, c_int, c_uint, c_ulong, c_void},
    os::unix::ffi::OsStrExt,
    ptr,
};
use symbols::Symbols;

fn with_libraries(soname: &str, run: impl FnOnce(&dyn Module, &Library)) {
    let cache = libraries::LibraryCache::new(false);
    let path = libraries::root_path(&cache, soname);
    let hosts = libraries::HostLibraries::new(&cache);
    let mut context = hosts.context();
    let linker = Linker::new().with_resolver(cache.resolver());
    let loaded = linker
        .run()
        .load(&mut context, Path::new(path.as_os_str().as_bytes()).into())
        .unwrap();
    // Both loaders open this exact system library. Keep both handles alive during the calls.
    let native = unsafe { Library::open(Some(&path), RTLD_NOW | RTLD_LOCAL) }.unwrap();
    run(context.module(loaded.root()).unwrap(), &native);
    drop(loaded.release(&mut context).unwrap());
}

// CRC-32 check vector (ISO-HDLC).
fn checksum(lib: &(impl Symbols + ?Sized)) -> c_ulong {
    let data = b"123456789";
    unsafe {
        let crc32: unsafe extern "C" fn(c_ulong, *const u8, c_uint) -> c_ulong =
            lib.symbol(c"crc32");
        crc32(0, data.as_ptr(), data.len() as c_uint)
    }
}

#[test]
fn zlib_checksum() {
    with_libraries("libz.so.1", |relink, native| {
        assert_eq!(checksum(native), 0xcbf43926);
        assert_eq!(checksum(relink), 0xcbf43926);
    });
}

fn parse_xml(lib: &(impl Symbols + ?Sized), xml: &str) -> c_int {
    // Use one Expat instance for the parser's entire lifetime.
    unsafe {
        let create: unsafe extern "C" fn(*const c_char) -> *mut c_void =
            lib.symbol(c"XML_ParserCreate");
        let parse: unsafe extern "C" fn(*mut c_void, *const c_char, c_int, c_int) -> c_int =
            lib.symbol(c"XML_Parse");
        let free: unsafe extern "C" fn(*mut c_void) = lib.symbol(c"XML_ParserFree");
        let parser = create(ptr::null());
        assert!(!parser.is_null());
        let status = parse(
            parser,
            xml.as_ptr().cast(),
            xml.len().try_into().unwrap(),
            1,
        );
        free(parser);
        status
    }
}

#[test]
fn expat_parse() {
    with_libraries("libexpat.so.1", |relink, native| {
        for (xml, expected) in [("<order><item/></order>", 1), ("<order></item>", 0)] {
            assert_eq!(parse_xml(native, xml), expected, "{xml}");
            assert_eq!(parse_xml(relink, xml), expected, "{xml}");
        }
    });
}
