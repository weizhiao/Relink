#![cfg(not(windows))]

#[path = "../examples/common/mod.rs"]
mod fixture_support;

use std::{fs, path::PathBuf as StdPathBuf};

use elf_loader::{
    input::{Path as ElfPath, PathBuf},
    linker::{CandidateRequest, LinkContext, Linker, SearchPathResolver},
};

#[test]
fn loads_fixture_chain() {
    let fixtures = fixture_support::ensure_all();
    let mut context = LinkContext::<PathBuf, ()>::new();

    let loaded = Linker::new()
        .resolver(fixture_support::search_path_resolver())
        .load(&mut context, PathBuf::from(fixtures.libc_str()))
        .unwrap();

    let c = unsafe { loaded.get::<fn() -> i32>("c").unwrap() };
    assert_eq!(c(), 3);
}

#[test]
fn supports_string_keys() {
    let fixtures = fixture_support::ensure_all();
    let mut context = LinkContext::<String, ()>::new();

    let loaded = Linker::new()
        .resolver(fixture_support::search_path_resolver())
        .load(&mut context, fixtures.libc_str().to_owned())
        .unwrap();

    let c = unsafe { loaded.get::<fn() -> i32>("c").unwrap() };
    assert_eq!(c(), 3);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn scan_first_loads_fixture_chain() {
    let fixtures = fixture_support::ensure_all();
    let mut context = LinkContext::<PathBuf, ()>::new();

    let loaded = Linker::new()
        .resolver(fixture_support::search_path_resolver())
        .load_scan_first(&mut context, PathBuf::from(fixtures.libc_str()))
        .unwrap();

    let c = unsafe { loaded.get::<fn() -> i32>("c").unwrap() };
    assert_eq!(c(), 3);
}

#[test]
fn dynamic_dirs_share_search_order_with_static_dirs() {
    let fixtures = fixture_support::ensure_all();
    let root = unique_test_dir("dynamic_order");
    let dynamic_dir = root.join("dynamic");
    let static_dir = root.join("static");
    fs::create_dir_all(&dynamic_dir).unwrap();
    fs::create_dir_all(&static_dir).unwrap();

    let dynamic_candidate = dynamic_dir.join("libpick.so");
    let static_candidate = static_dir.join("libpick.so");
    fs::copy(&fixtures.liba, &dynamic_candidate).unwrap();
    fs::copy(&fixtures.liba, &static_candidate).unwrap();

    let dynamic_dir = PathBuf::from(dynamic_dir.to_str().unwrap());
    let static_dir = PathBuf::from(static_dir.to_str().unwrap());
    let expected_key = dynamic_candidate.to_str().unwrap().to_owned();

    let mut resolver = SearchPathResolver::new();
    resolver.push_search_dir_provider(move |_, out| {
        out.push(dynamic_dir.clone());
        Ok(())
    });
    resolver.push_fixed_dir(static_dir);

    let mut context = LinkContext::<PathBuf, ()>::new();
    let loaded = Linker::new()
        .resolver(resolver)
        .load(&mut context, PathBuf::from("libpick.so"))
        .unwrap();

    assert_eq!(loaded.path().as_str(), expected_key);
}

#[test]
fn elf_dynamic_dirs_expand_origin_and_prefer_runpath() {
    let request = CandidateRequest::dependency(
        ElfPath::new("libdep.so"),
        "libowner.so",
        ElfPath::new("/tmp/owner/libowner.so"),
        Some("$ORIGIN/run:${ORIGIN}/alt"),
        Some("$ORIGIN/rpath"),
    );
    let runpath = request.runpath().expect("expected parsed runpath");
    let rpath = request.rpath().expect("expected parsed rpath");

    let runpath = runpath.iter().map(PathBuf::as_str).collect::<Vec<_>>();
    let rpath = rpath.iter().map(PathBuf::as_str).collect::<Vec<_>>();
    assert_eq!(runpath, ["/tmp/owner/run", "/tmp/owner/alt"]);
    assert_eq!(rpath, ["/tmp/owner/rpath"]);
}

fn unique_test_dir(name: &str) -> StdPathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "elf_loader_{name}_{}_{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    let _ = fs::remove_dir_all(&dir);
    dir
}
