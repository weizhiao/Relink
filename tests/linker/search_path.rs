use std::{fs, path::PathBuf as StdPathBuf};

use elf_loader::{
    LinkContext, Linker,
    input::{Path as ElfPath, PathBuf},
    linker::{CandidateRequest, SearchOwner, SearchPathResolver},
    runtime::DomainId,
};

#[test]
fn loads_dependency_chain() {
    let fixtures = crate::fixture::fixtures();
    let mut context = LinkContext::<PathBuf>::new(DomainId::PROCESS);

    let loaded = Linker::new()
        .resolver(crate::fixture::search_path_resolver())
        .load(
            &mut context,
            PathBuf::from(fixtures.root_path.to_str().unwrap()),
        )
        .unwrap();

    let root_value = unsafe { loaded.get::<extern "C" fn() -> i32>("root_value").unwrap() };
    assert_eq!(root_value(), 3);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn scan_loads_dependency_chain() {
    let fixtures = crate::fixture::fixtures();
    let mut context = LinkContext::<PathBuf>::new(DomainId::PROCESS);

    let loaded = Linker::new()
        .resolver(crate::fixture::search_path_resolver())
        .load_scan_first(
            &mut context,
            PathBuf::from(fixtures.root_path.to_str().unwrap()),
        )
        .unwrap();

    let root_value = unsafe { loaded.get::<extern "C" fn() -> i32>("root_value").unwrap() };
    assert_eq!(root_value(), 3);
}

#[test]
fn dynamic_dirs_precede_static_dirs() {
    let fixtures = crate::fixture::fixtures();
    let root = unique_test_dir("dynamic_order");
    let dynamic_dir = root.join("dynamic");
    let static_dir = root.join("static");
    fs::create_dir_all(&dynamic_dir).unwrap();
    fs::create_dir_all(&static_dir).unwrap();

    let dynamic_candidate = dynamic_dir.join("libpick.so");
    let static_candidate = static_dir.join("libpick.so");
    fs::copy(&fixtures.provider_path, &dynamic_candidate).unwrap();
    fs::copy(&fixtures.provider_path, &static_candidate).unwrap();

    let dynamic_dir = PathBuf::from(dynamic_dir.to_str().unwrap());
    let static_dir = PathBuf::from(static_dir.to_str().unwrap());
    let expected_key = dynamic_candidate.to_str().unwrap().to_owned();

    let mut resolver = SearchPathResolver::new();
    resolver.push_search_dir_provider(move |_, out| {
        out.push(dynamic_dir.clone());
        Ok(())
    });
    resolver.push_fixed_dir(static_dir);

    let mut context = LinkContext::<PathBuf>::new(DomainId::PROCESS);
    let loaded = Linker::new()
        .resolver(resolver)
        .load(&mut context, PathBuf::from("libpick.so"))
        .unwrap();

    assert_eq!(loaded.path().as_str(), expected_key);
}

#[test]
fn origin_expands_and_runpath_wins() {
    let request = CandidateRequest::dependency(
        ElfPath::new("libdep.so"),
        SearchOwner::new(
            "libowner.so",
            ElfPath::new("/tmp/owner/libowner.so"),
            Some("$ORIGIN/run:${ORIGIN}/alt"),
            Some("$ORIGIN/rpath"),
        ),
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
