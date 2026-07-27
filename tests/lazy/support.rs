use elf_loader::{
    Loader,
    arch::NativeArch,
    image::LoadedCore,
    input::ElfBinary,
    lazy::NativeLazyBinder,
    memory::{ImageMemoryExt, VmOffset},
    relocation::{RelocationArch, Relocator},
};
use object::{Object, ObjectSymbol, ObjectSymbolTable, RelocationFlags, RelocationTarget};

pub(crate) const FIRST: &str = "first";
pub(crate) const SECOND: &str = "second";
pub(crate) const CALL_FIRST: &str = "call_first";
pub(crate) const CALL_SECOND: &str = "call_second";
const JUMP_SLOT: u32 = <NativeArch as RelocationArch>::JUMP_SLOT.raw();
const LOADER: Loader = Loader::new();

type Image = LoadedCore<()>;
pub(crate) type Entry = extern "C" fn() -> i32;

pub(crate) fn load_provider() -> Image {
    Relocator::new()
        .run(
            LOADER
                .load_dylib(ElfBinary::new(
                    "provider.so",
                    &crate::fixture::fixtures().provider,
                ))
                .expect("failed to load lazy-binding provider"),
        )
        .relocate()
        .expect("failed to relocate lazy-binding provider")
}

pub(crate) fn load_lazy(provider: &Image) -> Image {
    Relocator::new()
        .lazy_binder(NativeLazyBinder::new())
        .run(
            LOADER
                .load_dylib(ElfBinary::new(
                    "consumer.so",
                    &crate::fixture::fixtures().consumer,
                ))
                .expect("failed to load lazy-binding consumer"),
        )
        .scope([provider])
        .relocate()
        .expect("failed to relocate lazy-binding consumer")
}

pub(crate) fn load_eager(provider: &Image) -> Image {
    Relocator::new()
        .run(
            LOADER
                .load_dylib(ElfBinary::new(
                    "consumer.so",
                    &crate::fixture::fixtures().now,
                ))
                .expect("failed to load bind-now consumer"),
        )
        .scope([provider])
        .relocate()
        .expect("failed to relocate bind-now consumer")
}

pub(crate) fn slot(image: &Image, bytes: &[u8], name: &str) -> u64 {
    let file = object::File::parse(bytes).expect("failed to parse lazy-binding fixture");
    let symbols = file
        .dynamic_symbol_table()
        .expect("lazy-binding fixture should have dynamic symbols");
    let offset = file
        .dynamic_relocations()
        .expect("lazy-binding fixture should have dynamic relocations")
        .find_map(|(offset, relocation)| {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                return None;
            };
            let symbol = symbols.symbol_by_index(index).ok()?;
            let RelocationFlags::Elf { r_type } = relocation.flags() else {
                return None;
            };
            (r_type == JUMP_SLOT && symbol.name_bytes().ok()? == name.as_bytes()).then_some(offset)
        })
        .unwrap_or_else(|| panic!("missing jump slot for {name}"));
    unsafe {
        image
            .segments()
            .read_value::<usize>(image.base() + VmOffset::new(offset as usize))
            .expect("failed to read lazy-binding slot") as u64
    }
}

pub(crate) fn symbol(image: &Image, name: &str) -> u64 {
    unsafe {
        image
            .get::<u8>(name)
            .unwrap_or_else(|| panic!("missing symbol {name}"))
            .into_raw() as u64
    }
}

pub(crate) fn call(image: &Image, name: &str) -> i32 {
    let function: Entry = unsafe {
        core::mem::transmute(
            image
                .get::<*const ()>(name)
                .unwrap_or_else(|| panic!("missing entry symbol {name}"))
                .into_raw(),
        )
    };
    function()
}
