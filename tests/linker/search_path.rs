use std::{fs, path::PathBuf as StdPathBuf};

use elf_loader::{
    Error, LinkContext, Linker,
    error::{LinkContextError, LinkerError},
    input::{Path as ElfPath, PathBuf},
    linker::{KeyMapper, SearchPathResolver},
    runtime::DomainId,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OpaqueKey(String);

struct OpaqueMapper;

impl KeyMapper<OpaqueKey> for OpaqueMapper {
    fn map_path(&self, candidate: &ElfPath) -> OpaqueKey {
        OpaqueKey(format!("path:{}", candidate.as_str()))
    }

    fn map_name(&self, name: &str) -> OpaqueKey {
        OpaqueKey(format!("name:{name}"))
    }
}

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

    let root_value = unsafe {
        context
            .module(loaded.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("root_value")
            .unwrap()
    };
    assert_eq!(root_value(), 3);
}

#[test]
fn maps_requests_and_names_separately() {
    let fixtures = crate::fixture::fixtures();
    let mut resolver = SearchPathResolver::with_mapper(OpaqueMapper);
    resolver.push_rpath().push_runpath();
    let mut context = LinkContext::<OpaqueKey>::new(DomainId::PROCESS);
    let linker = Linker::new().resolver(resolver);

    let loaded = linker
        .load(
            &mut context,
            PathBuf::from(fixtures.root_path.to_str().unwrap()),
        )
        .unwrap();

    let root_value = unsafe {
        context
            .module(loaded.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("root_value")
            .unwrap()
    };
    assert_eq!(root_value(), 3);

    let leaf = linker
        .load(
            &mut context,
            PathBuf::from(fixtures.rpath_leaf_path.to_str().unwrap()),
        )
        .unwrap();
    assert_eq!(
        context.module_id(&OpaqueKey("name:libleaf.so".into())),
        Some(leaf.root())
    );
}

#[test]
fn inherits_rpath() {
    let fixtures = crate::fixture::fixtures();
    let mut context = LinkContext::<PathBuf>::new(DomainId::PROCESS);

    let loaded = Linker::new()
        .resolver(crate::fixture::search_path_resolver())
        .load(
            &mut context,
            PathBuf::from(fixtures.rpath_root_path.to_str().unwrap()),
        )
        .unwrap();

    let search = context
        .module(loaded.root())
        .unwrap()
        .search()
        .expect("loaded ELF modules should retain search metadata");
    assert_eq!(
        search.path().as_str(),
        fixtures.rpath_root_path.to_str().unwrap()
    );
    let expected_rpath = fixtures
        .rpath_root_path
        .parent()
        .unwrap()
        .join("rpath")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        search
            .rpath()
            .unwrap()
            .map(ElfPath::as_str)
            .collect::<Vec<_>>(),
        [expected_rpath]
    );
    assert!(search.runpath().is_none());

    let value = unsafe {
        context
            .module(loaded.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("rpath_value")
            .unwrap()
    };
    assert_eq!(value(), 3);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn scan_inherits_rpath() {
    let fixtures = crate::fixture::fixtures();
    let mut context = LinkContext::<PathBuf>::new(DomainId::PROCESS);

    let loaded = Linker::new()
        .resolver(crate::fixture::search_path_resolver())
        .load_scan_first(
            &mut context,
            PathBuf::from(fixtures.rpath_root_path.to_str().unwrap()),
        )
        .unwrap();

    let value = unsafe {
        context
            .module(loaded.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("rpath_value")
            .unwrap()
    };
    assert_eq!(value(), 3);
}

#[test]
fn loads_from_module_rpath() {
    let fixtures = crate::fixture::fixtures();
    let mut context = LinkContext::<PathBuf>::new(DomainId::PROCESS);
    let linker = Linker::new().resolver(crate::fixture::search_path_resolver());

    let caller = linker
        .load(
            &mut context,
            PathBuf::from(fixtures.rpath_caller_path.to_str().unwrap()),
        )
        .unwrap();
    let loaded = linker
        .load_from(&mut context, PathBuf::from("libleaf.so"), caller.root())
        .unwrap();

    let value = unsafe {
        context
            .module(loaded.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("rpath_leaf")
            .unwrap()
    };
    assert_eq!(value(), 1);
}

#[test]
fn reuses_soname() {
    let fixtures = crate::fixture::fixtures();
    let dir = unique_test_dir("soname");
    fs::create_dir_all(&dir).unwrap();
    let alias = dir.join("leaf-implementation.so");
    fs::copy(&fixtures.rpath_leaf_path, &alias).unwrap();

    let mut context = LinkContext::<PathBuf>::new(DomainId::PROCESS);
    let linker = Linker::new().resolver(crate::fixture::search_path_resolver());
    let first = linker
        .load(&mut context, PathBuf::from(alias.to_str().unwrap()))
        .unwrap();
    let duplicate = linker
        .load(
            &mut context,
            PathBuf::from(fixtures.rpath_leaf_path.to_str().unwrap()),
        )
        .unwrap();
    assert_ne!(first.root(), duplicate.root());

    let by_name = linker
        .load(&mut context, PathBuf::from("libleaf.so"))
        .unwrap();
    assert_eq!(first.root(), by_name.root());
    by_name.release(&mut context).unwrap();
    first.release(&mut context).unwrap();

    let by_name = linker
        .load(&mut context, PathBuf::from("libleaf.so"))
        .unwrap();
    assert_eq!(duplicate.root(), by_name.root());
    assert_eq!(context.load_order().count(), 1);

    let root = linker
        .load(
            &mut context,
            PathBuf::from(fixtures.rpath_root_path.to_str().unwrap()),
        )
        .unwrap();
    let value = unsafe {
        context
            .module(root.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("rpath_value")
            .unwrap()
    };
    assert_eq!(value(), 3);
    assert_eq!(context.load_order().count(), 3);
}

#[test]
fn reuses_file() {
    let fixtures = crate::fixture::fixtures();
    let alias_path = fixtures
        .rpath_leaf_path
        .with_file_name(format!("libleaf-file-id-{}.so", std::process::id()));
    let _ = fs::remove_file(&alias_path);
    fs::hard_link(&fixtures.rpath_leaf_path, &alias_path).unwrap();

    let original = PathBuf::from(fixtures.rpath_leaf_path.to_str().unwrap());
    let alias = PathBuf::from(alias_path.to_str().unwrap());
    let mut context = LinkContext::<PathBuf>::new(DomainId::PROCESS);
    let linker = Linker::new().resolver(crate::fixture::search_path_resolver());
    let first = linker.load(&mut context, original.clone()).unwrap();
    let second = linker.load(&mut context, alias.clone()).unwrap();

    assert_eq!(first.root(), second.root());
    assert_eq!(context.module_id(&original), Some(first.root()));
    assert_eq!(context.module_id(&alias), Some(first.root()));
    assert_eq!(context.load_order().count(), 1);

    let old = first.root();
    second.release(&mut context).unwrap();
    first.release(&mut context).unwrap();
    assert!(context.is_empty());

    let reloaded = linker.load(&mut context, alias).unwrap();
    assert_ne!(reloaded.root(), old);
    assert_eq!(context.load_order().count(), 1);
    reloaded.release(&mut context).unwrap();
    fs::remove_file(alias_path).unwrap();
}

#[test]
fn imports_reuse_file() {
    let fixtures = crate::fixture::fixtures();
    let alias_path = fixtures
        .rpath_leaf_path
        .with_file_name(format!("libleaf-index-{}.so", std::process::id()));
    let next_path = fixtures
        .rpath_leaf_path
        .with_file_name(format!("libleaf-next-{}.so", std::process::id()));
    let _ = fs::remove_file(&alias_path);
    let _ = fs::remove_file(&next_path);
    fs::hard_link(&fixtures.rpath_leaf_path, &alias_path).unwrap();
    fs::hard_link(&fixtures.rpath_leaf_path, &next_path).unwrap();

    let original = PathBuf::from(fixtures.rpath_leaf_path.to_str().unwrap());
    let alias = PathBuf::from(alias_path.to_str().unwrap());
    let next = PathBuf::from(next_path.to_str().unwrap());
    let linker = Linker::new().resolver(crate::fixture::search_path_resolver());
    let mut source = LinkContext::<PathBuf>::new(DomainId::PROCESS);
    let source_module = linker.load(&mut source, original).unwrap();
    let mut target = LinkContext::<PathBuf>::new(DomainId::PROCESS);
    let first = linker.load(&mut target, alias).unwrap();
    let imported = target.import(&source, source_module.root()).unwrap();
    assert_eq!(imported.id(), first.root());
    assert_eq!(target.load_order().count(), 1);

    first.release(&mut target).unwrap();
    let reused = linker.load(&mut target, next).unwrap();
    assert_eq!(reused.root(), imported.id());
    assert_eq!(target.load_order().count(), 1);

    reused.release(&mut target).unwrap();
    target.release(imported).unwrap();
    fs::remove_file(alias_path).unwrap();
    fs::remove_file(next_path).unwrap();
}

#[test]
fn rejects_reloaded_file() {
    let fixtures = crate::fixture::fixtures();
    let alias_path = fixtures
        .rpath_leaf_path
        .with_file_name(format!("libleaf-stale-{}.so", std::process::id()));
    let _ = fs::remove_file(&alias_path);
    fs::hard_link(&fixtures.rpath_leaf_path, &alias_path).unwrap();

    let original = PathBuf::from(fixtures.rpath_leaf_path.to_str().unwrap());
    let alias = PathBuf::from(alias_path.to_str().unwrap());
    let linker = Linker::new().resolver(crate::fixture::search_path_resolver());
    let mut context = LinkContext::<PathBuf>::new(DomainId::PROCESS);
    let mut run = linker.run();
    let loaded = run.load(&mut context, original.clone()).unwrap();
    let prepared = run.prepare_load(&mut context, alias).unwrap();
    let relocated = run.relocate(prepared).unwrap();

    loaded.release(&mut context).unwrap();
    let replacement = run.load(&mut context, original).unwrap();
    let error = relocated
        .publish(&mut context)
        .expect_err("reloaded file must invalidate the prepared transaction");
    let Error::Linker(LinkerError::Context { reason }) = error else {
        panic!("unexpected publication error: {error}");
    };
    assert!(matches!(*reason, LinkContextError::ModuleChanged { .. }));
    replacement.release(&mut context).unwrap();
    fs::remove_file(alias_path).unwrap();
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

    let root_value = unsafe {
        context
            .module(loaded.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("root_value")
            .unwrap()
    };
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

    assert_eq!(
        context
            .module(loaded.root())
            .unwrap()
            .search()
            .unwrap()
            .path()
            .as_str(),
        expected_key
    );
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
