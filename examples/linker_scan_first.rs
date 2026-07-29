#[path = "support/mod.rs"]
mod fixture_support;

use elf_loader::{
    LinkContext, Linker, Result,
    image::{Module, ModuleCapability},
    input::PathBuf,
    linker::scan::{LinkPass, LinkPassPlan, Materialization, ReorderPass},
    runtime::DomainId,
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

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let fixtures = fixture_support::ensure_all();
    let mut context: LinkContext<PathBuf, ()> = LinkContext::new(DomainId::PROCESS);

    let loaded = Linker::new()
        .resolver(fixture_support::search_path_resolver())
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(ConfigureRootSectionRegions);
            pipeline
        })
        .load_scan_first(&mut context, PathBuf::from(fixtures.leaf_str()))?;

    let leaf_value = unsafe { loaded.get::<extern "C" fn() -> i32>("leaf_value").unwrap() };
    let value = leaf_value();
    assert_eq!(value, 3);
    println!(
        "scan-first loaded {} with {} committed modules; leaf_value() = {}",
        loaded.name(),
        loaded.modules().len(),
        value
    );

    Ok(())
}
