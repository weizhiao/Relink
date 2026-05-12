#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Result,
    image::ModuleCapability,
    input::PathBuf,
    linker::{LinkContext, LinkPass, LinkPassPlan, Linker, Materialization, ReorderPass},
};
use std::collections::HashMap;

struct ConfigureRootSectionRegions;

impl LinkPass<PathBuf, ReorderPass> for ConfigureRootSectionRegions {
    fn run(&mut self, plan: &mut LinkPassPlan<'_, PathBuf, ReorderPass>) -> Result<()> {
        let root = plan.root().expect("root module should be visible");
        assert_eq!(root.capability(plan), ModuleCapability::SectionReorderable,);
        root.set_materialization(plan, Materialization::SectionRegions);
        Ok(())
    }
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    fn print(s: &str) {
        println!("{}", s);
    }

    let mut symbols = HashMap::new();
    symbols.insert("print", print as *const ());
    let pre_find = |name: &str| -> Option<*const ()> { symbols.get(name).copied() };

    let fixtures = fixture_support::ensure_all();
    let mut context = LinkContext::<PathBuf, ()>::new();

    let loaded = Linker::new()
        .resolver(fixture_support::search_path_resolver())
        .map_pipeline(|mut pipeline| {
            pipeline.push(ConfigureRootSectionRegions);
            pipeline
        })
        .map_relocator(|relocator| relocator.pre_find(&pre_find))
        .load_scan_first(&mut context, PathBuf::from(fixtures.libc_str()))?;

    let c = unsafe { loaded.get::<fn() -> i32>("c").unwrap() };
    assert!(c() == 3);

    Ok(())
}
