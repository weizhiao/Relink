#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Result,
    image::ModuleCapability,
    input::ElfFile,
    linker::{
        DependencyRequest, KeyResolver, LinkContext, LinkPassPlan, Linker, Materialization,
        ReorderPass, ResolvedKey,
    },
};
use std::collections::HashMap;

struct FixtureResolver {
    liba: String,
    libb: String,
    libc: String,
}

impl KeyResolver<'static, &'static str, ()> for FixtureResolver {
    fn load_root(&mut self, key: &&'static str) -> Result<ResolvedKey<'static, &'static str>> {
        let path = match *key {
            "liba" => &self.liba,
            "libb" => &self.libb,
            "libc" => &self.libc,
            _ => panic!("unexpected fixture key: {key}"),
        };
        Ok(ResolvedKey::load(*key, ElfFile::from_path(path)?))
    }

    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, &'static str, ()>,
    ) -> Result<Option<ResolvedKey<'static, &'static str>>> {
        let resolved = match req.needed() {
            "liba.so" => ResolvedKey::load("liba", ElfFile::from_path(&self.liba)?),
            "libb.so" => ResolvedKey::load("libb", ElfFile::from_path(&self.libb)?),
            _ => return Ok(None),
        };
        Ok(Some(resolved))
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
    let resolver = FixtureResolver {
        liba: fixtures.liba_str().to_owned(),
        libb: fixtures.libb_str().to_owned(),
        libc: fixtures.libc_str().to_owned(),
    };
    let mut context = LinkContext::<&'static str, ()>::new();

    let configure = |plan: &mut LinkPassPlan<'_, &'static str, (), ReorderPass>| -> Result<()> {
        let root = plan.root();
        assert_eq!(
            plan.capability(root),
            Some(ModuleCapability::SectionReorderable),
        );
        plan.set_materialization(root, Materialization::SectionRegions);
        Ok(())
    };

    let loaded = Linker::new()
        .resolver(resolver)
        .map_pipeline(|mut pipeline| {
            pipeline.push(configure);
            pipeline
        })
        .map_relocator(|relocator| relocator.pre_find(&pre_find))
        .load_scan_first(&mut context, "libc")?;

    let _c = unsafe { loaded.get::<fn() -> i32>("c").unwrap() };
    assert!(context.contains_key(&"libb"));
    println!(
        "Loaded {} with scan-first section layout and DT_NEEDED libb.",
        loaded.name()
    );

    Ok(())
}
