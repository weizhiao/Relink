#[path = "../examples/common/mod.rs"]
mod fixture_support;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use elf_loader::{
    Loader, Result,
    image::{LoadedCore, ModuleCapability},
    input::ElfFile,
    linker::{
        LinkContext, LinkPass, LinkPassPlan, Linker, Materialization, ReorderPass,
        SearchPathResolver,
    },
};
use libloading::os::unix::{Library as UnixLibrary, RTLD_LAZY, RTLD_LOCAL, RTLD_NOW};
use std::{fs, hint::black_box};

struct FixtureBytes {
    liba: Vec<u8>,
    libb: Vec<u8>,
    libc: Vec<u8>,
}

impl FixtureBytes {
    fn new(fixtures: &fixture_support::FixturePaths) -> Self {
        Self {
            liba: fs::read(&fixtures.liba).expect("failed to read liba fixture"),
            libb: fs::read(&fixtures.libb).expect("failed to read libb fixture"),
            libc: fs::read(&fixtures.libc).expect("failed to read libc fixture"),
        }
    }
}

struct UseRootSectionRegions;

impl LinkPass<String, ReorderPass> for UseRootSectionRegions {
    fn run(&mut self, plan: &mut LinkPassPlan<'_, String, ReorderPass>) -> Result<()> {
        let root = plan.root().expect("root module should be visible");
        assert_eq!(root.capability(plan), ModuleCapability::SectionReorderable);
        root.set_materialization(plan, Materialization::SectionRegions);
        Ok(())
    }
}

fn load_manual_file(fixtures: &fixture_support::FixturePaths) -> LoadedCore<()> {
    let mut loader = Loader::new();
    let liba = loader
        .load_dylib(ElfFile::from_path(black_box(fixtures.liba_str())).unwrap())
        .unwrap()
        .relocator()
        .relocate()
        .unwrap();
    let libb = loader
        .load_dylib(ElfFile::from_path(black_box(fixtures.libb_str())).unwrap())
        .unwrap()
        .relocator()
        .scope([&liba])
        .relocate()
        .unwrap();
    loader
        .load_dylib(ElfFile::from_path(black_box(fixtures.libc_str())).unwrap())
        .unwrap()
        .relocator()
        .scope([&liba, &libb])
        .relocate()
        .unwrap()
}

fn load_manual_memory(fixtures: &FixtureBytes) -> LoadedCore<()> {
    let mut loader = Loader::new();
    let liba = loader
        .load_dylib(black_box(fixtures.liba.as_slice()))
        .unwrap()
        .relocator()
        .relocate()
        .unwrap();
    let libb = loader
        .load_dylib(black_box(fixtures.libb.as_slice()))
        .unwrap()
        .relocator()
        .scope([&liba])
        .relocate()
        .unwrap();
    loader
        .load_dylib(black_box(fixtures.libc.as_slice()))
        .unwrap()
        .relocator()
        .scope([&liba, &libb])
        .relocate()
        .unwrap()
}

fn load_linker(root: String) {
    let mut context = LinkContext::<String, ()>::new();
    let loaded = Linker::new()
        .resolver(SearchPathResolver::new())
        .load(&mut context, black_box(root))
        .unwrap();
    black_box(loaded);
}

fn load_scan_first(root: String) {
    let mut context = LinkContext::<String, ()>::new();
    let loaded = Linker::new()
        .resolver(SearchPathResolver::new())
        .map_pipeline(|mut pipeline| {
            pipeline.push(UseRootSectionRegions);
            pipeline
        })
        .load_scan_first(&mut context, black_box(root))
        .unwrap();
    black_box(loaded);
}

fn dlopen_libc(fixtures: &fixture_support::FixturePaths, flags: i32) {
    let library = unsafe { UnixLibrary::open(Some(black_box(&fixtures.libc)), flags).unwrap() };
    black_box(library);
}

fn bench_load(c: &mut Criterion) {
    let fixtures = fixture_support::ensure_all();
    let fixture_bytes = FixtureBytes::new(&fixtures);

    let mut group = c.benchmark_group("load");
    group.bench_function("elf_loader/file", |b| {
        b.iter(|| black_box(load_manual_file(&fixtures)));
    });
    group.bench_function("elf_loader/memory", |b| {
        b.iter(|| black_box(load_manual_memory(&fixture_bytes)));
    });
    group.bench_function("linker/runtime", |b| {
        b.iter_batched(
            || fixtures.libc_str().to_owned(),
            load_linker,
            BatchSize::SmallInput,
        );
    });
    group.bench_function("linker/scan_first", |b| {
        b.iter_batched(
            || fixtures.libc_str().to_owned(),
            load_scan_first,
            BatchSize::SmallInput,
        );
    });
    group.bench_function("libloading/lazy", |b| {
        b.iter(|| dlopen_libc(&fixtures, RTLD_LAZY | RTLD_LOCAL));
    });
    group.bench_function("libloading/now", |b| {
        b.iter(|| dlopen_libc(&fixtures, RTLD_NOW | RTLD_LOCAL));
    });
    group.finish();
}

fn bench_symbol(c: &mut Criterion) {
    let fixtures = fixture_support::ensure_all();
    let libc = load_manual_file(&fixtures);
    let dlopen_libc =
        unsafe { UnixLibrary::open(Some(&fixtures.libc), RTLD_NOW | RTLD_LOCAL).unwrap() };

    let mut group = c.benchmark_group("symbol");
    group.bench_function("elf_loader/hit", |b| {
        b.iter(|| unsafe {
            black_box(libc.get::<fn() -> i32>(black_box("c")).unwrap());
        });
    });
    group.bench_function("elf_loader/miss", |b| {
        b.iter(|| unsafe {
            black_box(
                libc.get::<fn() -> i32>(black_box("missing_symbol"))
                    .is_none(),
            );
        });
    });
    group.bench_function("libloading/hit", |b| {
        b.iter(|| unsafe {
            black_box(dlopen_libc.get::<fn() -> i32>(black_box(b"c")).unwrap());
        });
    });
    group.bench_function("libloading/miss", |b| {
        b.iter(|| unsafe {
            black_box(
                dlopen_libc
                    .get::<fn() -> i32>(black_box(b"missing_symbol"))
                    .is_err(),
            );
        });
    });
    group.finish();
}

criterion_group!(benches, bench_load, bench_symbol);
criterion_main!(benches);
