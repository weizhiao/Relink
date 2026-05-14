mod support;

#[cfg(feature = "lazy-binding")]
use elf_loader::{
    Loader, arch::NativeArch, image::LoadedCore, input::ElfBinary, relocation::RelocationArch,
};

#[cfg(feature = "lazy-binding")]
const REL_GOT: u32 = <NativeArch as RelocationArch>::GOT.raw();
#[cfg(feature = "lazy-binding")]
const REL_JUMP_SLOT: u32 = <NativeArch as RelocationArch>::JUMP_SLOT.raw();
#[cfg(feature = "lazy-binding")]
use gen_elf::ElfWriterConfig;
#[cfg(feature = "lazy-binding")]
use gen_elf::{Arch, ElfWriteOutput, RelocEntry, SymbolDesc};
#[cfg(feature = "lazy-binding")]
use support::binding::{BindingFixture, BindingKind};
#[cfg(feature = "lazy-binding")]
use support::{
    dylib_relocation_checks::{relocation_for_symbol, slot_word},
    generated_dylib::return_42_stub,
    test_dylib::{load_relocated_dylib, write_test_dylib, write_test_dylib_with_config},
};

#[cfg(feature = "lazy-binding")]
const SCOPED_FUNC_NAME: &str = "scoped_func";
#[cfg(feature = "lazy-binding")]
const SCOPED_VAR_NAME: &str = "scoped_var";

#[cfg(feature = "lazy-binding")]
type ScopedHelperFn = extern "C" fn() -> i32;

#[cfg(feature = "lazy-binding")]
fn write_scope_provider() -> ElfWriteOutput {
    let arch = Arch::current();
    write_test_dylib(
        &[],
        &[
            SymbolDesc::global_func(SCOPED_FUNC_NAME, &return_42_stub(arch)),
            SymbolDesc::global_object(SCOPED_VAR_NAME, &[0x12, 0x34, 0x56, 0x78]),
        ],
    )
}

#[cfg(feature = "lazy-binding")]
fn write_scope_consumer(config: ElfWriterConfig) -> ElfWriteOutput {
    let arch = Arch::current();
    write_test_dylib_with_config(
        config,
        &[
            RelocEntry::glob_dat(SCOPED_VAR_NAME, arch),
            RelocEntry::jump_slot(SCOPED_FUNC_NAME, arch),
        ],
        &[
            SymbolDesc::undefined_object(SCOPED_VAR_NAME),
            SymbolDesc::undefined_func(SCOPED_FUNC_NAME),
        ],
    )
}

#[cfg(feature = "lazy-binding")]
fn write_scope_func_consumer(config: ElfWriterConfig) -> ElfWriteOutput {
    let arch = Arch::current();
    write_test_dylib_with_config(
        config,
        &[RelocEntry::jump_slot(SCOPED_FUNC_NAME, arch)],
        &[SymbolDesc::undefined_func(SCOPED_FUNC_NAME)],
    )
}

#[cfg(feature = "lazy-binding")]
fn scope_symbol_address(image: &LoadedCore<()>, symbol_name: &str) -> u64 {
    unsafe {
        image
            .get::<*const ()>(symbol_name)
            .unwrap_or_else(|| panic!("missing scoped symbol {symbol_name}"))
            .into_raw() as u64
    }
}

#[cfg(feature = "lazy-binding")]
fn jump_slot_word(image: &LoadedCore<()>, output: &ElfWriteOutput) -> u64 {
    slot_word(
        image,
        relocation_for_symbol(output, REL_JUMP_SLOT, SCOPED_FUNC_NAME),
    )
}

#[cfg(feature = "lazy-binding")]
fn got_slot_word(image: &LoadedCore<()>, output: &ElfWriteOutput) -> u64 {
    slot_word(
        image,
        relocation_for_symbol(output, REL_GOT, SCOPED_VAR_NAME),
    )
}

#[cfg(feature = "lazy-binding")]
fn call_scope_helper(image: &LoadedCore<()>) -> i32 {
    let helper_name = format!("{SCOPED_FUNC_NAME}@plt_helper");
    let helper_fn: ScopedHelperFn = unsafe {
        core::mem::transmute(
            image
                .get::<*const ()>(&helper_name)
                .unwrap_or_else(|| panic!("missing helper symbol {helper_name}"))
                .into_raw(),
        )
    };
    helper_fn()
}

#[cfg(feature = "lazy-binding")]
#[test]
fn lazy_jump_slots_resolve() {
    let scenario = BindingFixture::new().load(BindingKind::Lazy);

    scenario.assert_single_dependency();
    scenario.assert_non_plt_relocations();
    scenario.assert_relative_relocations();
    scenario.assert_lazy_jump_slots();
    #[cfg(feature = "tls")]
    scenario.assert_tls_relocations();
}

#[cfg(feature = "lazy-binding")]
#[test]
fn default_lazy_binding_uses_retained_scope_dependency() {
    let mut loader = Loader::new();
    let provider_output = write_scope_provider();
    let provider = load_relocated_dylib(&mut loader, "libscope_provider.so", &provider_output);
    let consumer_output = write_scope_consumer(ElfWriterConfig::default());

    let relocated = loader
        .load_dylib(ElfBinary::new("scope_consumer.so", &consumer_output.data))
        .expect("failed to load scope consumer")
        .relocator()
        .scope(&[provider.clone()])
        .relocate()
        .expect("failed to relocate scope consumer");

    let scoped_func_addr = scope_symbol_address(&provider, SCOPED_FUNC_NAME);
    let scoped_var_addr = scope_symbol_address(&provider, SCOPED_VAR_NAME);
    assert_eq!(got_slot_word(&relocated, &consumer_output), scoped_var_addr);
    assert_ne!(
        jump_slot_word(&relocated, &consumer_output),
        scoped_func_addr,
        "default lazy binding should leave the jump slot unresolved before the first call"
    );
    assert_eq!(call_scope_helper(&relocated), 42);
    assert_eq!(
        jump_slot_word(&relocated, &consumer_output),
        scoped_func_addr
    );
    let deps = relocated.deps().collect::<Vec<_>>();
    assert_eq!(deps.len(), 1, "expected one retained dependency");
    assert_eq!(deps[0].name(), provider.name());
}

#[cfg(feature = "lazy-binding")]
#[test]
fn default_lazy_binding_retains_scope_used_only_by_lazy_jump_slot() {
    let mut loader = Loader::new();
    let provider_output = write_scope_provider();
    let provider = load_relocated_dylib(&mut loader, "libscope_provider.so", &provider_output);
    let consumer_output = write_scope_func_consumer(ElfWriterConfig::default());

    let relocated = loader
        .load_dylib(ElfBinary::new(
            "scope_func_consumer.so",
            &consumer_output.data,
        ))
        .expect("failed to load scope consumer")
        .relocator()
        .scope(&[provider.clone()])
        .relocate()
        .expect("failed to relocate scope consumer");

    let scoped_func_addr = scope_symbol_address(&provider, SCOPED_FUNC_NAME);
    assert_ne!(
        jump_slot_word(&relocated, &consumer_output),
        scoped_func_addr,
        "default lazy binding should leave the jump slot unresolved before the first call"
    );
    let deps = relocated.deps().collect::<Vec<_>>();
    assert_eq!(
        deps.len(),
        1,
        "lazy jump slot scope dependency should be retained before first call"
    );
    assert_eq!(deps[0].name(), provider.name());
    assert_eq!(call_scope_helper(&relocated), 42);
    assert_eq!(
        jump_slot_word(&relocated, &consumer_output),
        scoped_func_addr
    );
}

#[cfg(feature = "lazy-binding")]
#[test]
fn bind_now_defaults_to_eager_resolution() {
    let mut loader = Loader::new();
    let provider_output = write_scope_provider();
    let provider = load_relocated_dylib(&mut loader, "libscope_provider.so", &provider_output);
    let consumer_output = write_scope_consumer(ElfWriterConfig::default().with_bind_now(true));

    let relocated = loader
        .load_dylib(ElfBinary::new("scope_consumer.so", &consumer_output.data))
        .expect("failed to load scope consumer")
        .relocator()
        .scope(&[provider.clone()])
        .relocate()
        .expect("failed to relocate scope consumer");

    let scoped_func_addr = scope_symbol_address(&provider, SCOPED_FUNC_NAME);
    let scoped_var_addr = scope_symbol_address(&provider, SCOPED_VAR_NAME);
    assert_eq!(got_slot_word(&relocated, &consumer_output), scoped_var_addr);
    assert_eq!(
        jump_slot_word(&relocated, &consumer_output),
        scoped_func_addr,
        "bind-now should resolve the jump slot during relocate()"
    );
    assert_eq!(call_scope_helper(&relocated), 42);
    let deps = relocated.deps().collect::<Vec<_>>();
    assert_eq!(deps.len(), 1, "expected one retained dependency");
    assert_eq!(deps[0].name(), provider.name());
}
