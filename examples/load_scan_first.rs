#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Result,
    image::{ModuleCapability, SyntheticModule, SyntheticSymbol},
    input::PathBuf,
    linker::{
        LinkContext, LinkPass, LinkPassPlan, Linker, Materialization, RelocationInputs,
        RelocationRequest, ReorderPass,
    },
};

struct ConfigureRootSectionRegions;

impl LinkPass<PathBuf, ReorderPass> for ConfigureRootSectionRegions {
    fn run(&mut self, plan: &mut LinkPassPlan<'_, PathBuf, ReorderPass>) -> Result<()> {
        let root = plan.root().expect("root module should be visible");
        assert_eq!(root.capability(plan), ModuleCapability::SectionReorderable,);
        root.set_materialization(plan, Materialization::SectionRegions);
        Ok(())
    }
}

fn host_symbols() -> SyntheticModule {
    fn print(s: &str) {
        println!("{}", s);
    }

    SyntheticModule::new(
        "__host",
        [SyntheticSymbol::function("print", print as *const ())],
    )
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let fixtures = fixture_support::ensure_all();
    let mut context = LinkContext::<PathBuf, ()>::new();

    let loaded = Linker::new()
        .resolver(fixture_support::search_path_resolver())
        .map_pipeline(|mut pipeline| {
            pipeline.push(ConfigureRootSectionRegions);
            pipeline
        })
        .planner(|req: &RelocationRequest<'_, PathBuf, ()>| {
            Ok(RelocationInputs::scope(
                req.scope().extend([host_symbols()]),
            ))
        })
        .load_scan_first(&mut context, PathBuf::from(fixtures.libc_str()))?;

    let c = unsafe { loaded.get::<fn() -> i32>("c").unwrap() };
    assert!(c() == 3);

    Ok(())
}
