use elf_loader::{
    LinkContext, Linker, Result,
    error::CustomError,
    image::ModuleCapability,
    input::PathBuf,
    linker::{
        SearchPathResolver,
        scan::{LinkPass, LinkPassPlan, Materialization, ReorderPass},
    },
};
use std::ffi::c_int;

const LIBRARY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/example-library/libexample.so"
);

struct ConfigureRootSectionRegions;

impl LinkPass<ReorderPass> for ConfigureRootSectionRegions {
    fn run(&mut self, plan: &mut LinkPassPlan<'_, ReorderPass>) -> Result<()> {
        let root = plan.root().expect("root module should be visible");
        if root.capability(plan) != ModuleCapability::SectionReorderable {
            return Err(elf_loader::Error::Custom(CustomError::message(
                "section placement requires retained relocations on x86-64; see examples/README.md",
            )));
        }
        root.set_materialization(plan, Materialization::SectionRegions);
        Ok(())
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let mut context = LinkContext::for_process();
    let loaded = Linker::new()
        .with_resolver(SearchPathResolver::new())
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(ConfigureRootSectionRegions);
            pipeline
        })
        .load_scan_first(&mut context, PathBuf::from(LIBRARY))?;

    let module = context.module(loaded.root())?;
    // SAFETY: examples/library/example.c defines int example_value(void).
    let value = unsafe {
        let function = module
            .get::<unsafe extern "C" fn() -> c_int>("example_value")?
            .ok_or("missing example_value")?;
        function()
    };
    println!(
        "scan-first loaded {} with {} new modules using section regions; example_value() = {value}",
        module.name().escape_ascii(),
        loaded.modules().len(),
    );
    drop(loaded.release(&mut context)?);
    Ok(())
}
