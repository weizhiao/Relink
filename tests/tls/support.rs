use std::sync::OnceLock;

use elf_loader::{
    Loader,
    arch::NativeArch,
    image::LoadedCore,
    input::ElfBinary,
    memory::{HostRegion, ImageMemoryExt, VmOffset},
    relocation::{RelocationArch, Relocator},
    tls::DefaultTlsResolver,
};
use gen_elf::{
    Arch, DylibWriter, ElfWriteOutput, ElfWriterConfig, RelocEntry, RelocationInfo, SymbolDesc,
};

pub(crate) const FIRST: &str = "first";
pub(crate) const SECOND: &str = "second";
pub(crate) const DTPMOD: u32 = <NativeArch as RelocationArch>::DTPMOD.unwrap().raw();
pub(crate) const DTPOFF: u32 = <NativeArch as RelocationArch>::DTPOFF.raw();

type TlsImage = LoadedCore<(), NativeArch, HostRegion, DefaultTlsResolver>;
pub(crate) type TlsHelper = extern "C" fn() -> *mut u32;

pub(crate) struct TlsScenario {
    output: ElfWriteOutput,
    provider: TlsImage,
    consumer: TlsImage,
}

impl TlsScenario {
    pub(crate) fn provider(&self) -> &TlsImage {
        &self.provider
    }

    pub(crate) fn relocation(&self, r_type: u32, name: &str) -> &RelocationInfo {
        self.output
            .find_relocation(r_type, name)
            .unwrap_or_else(|| panic!("missing relocation type {r_type} for symbol {name}"))
    }

    pub(crate) fn slot(&self, relocation: &RelocationInfo) -> u64 {
        let addr = self.consumer.segments().base()
            + VmOffset::new(
                relocation
                    .vaddr
                    .expect("dynamic relocation should have a virtual address")
                    as usize,
            );
        unsafe {
            self.consumer
                .segments()
                .read_value::<usize>(addr)
                .expect("failed to read TLS relocation slot") as u64
        }
    }

    pub(crate) fn helper(&self, name: &str) -> TlsHelper {
        let name = format!("{name}@tls_helper");
        unsafe {
            core::mem::transmute(
                self.consumer
                    .get::<*const ()>(&name)
                    .unwrap_or_else(|| panic!("missing TLS helper symbol {name}"))
                    .into_raw(),
            )
        }
    }
}

pub(crate) fn scenario() -> &'static TlsScenario {
    static SCENARIO: OnceLock<TlsScenario> = OnceLock::new();
    SCENARIO.get_or_init(load)
}

fn load() -> TlsScenario {
    let arch = Arch::current();
    let config = || ElfWriterConfig::default().with_bind_now(true);
    let provider = DylibWriter::with_config(arch, config())
        .write(
            &[],
            &[
                SymbolDesc::global_tls(FIRST, &[0xAA, 0xBB, 0xCC, 0xDD]),
                SymbolDesc::global_tls(SECOND, &[0x11, 0x22, 0x33, 0x44]),
            ],
        )
        .expect("failed to generate TLS provider");
    let output = DylibWriter::with_config(arch, config())
        .write(
            &[
                RelocEntry::with_name(FIRST, DTPMOD),
                RelocEntry::with_name(FIRST, DTPOFF),
                RelocEntry::with_name(SECOND, DTPMOD),
                RelocEntry::with_name(SECOND, DTPOFF),
            ],
            &[
                SymbolDesc::undefined_tls(FIRST),
                SymbolDesc::undefined_tls(SECOND),
            ],
        )
        .expect("failed to generate TLS consumer");
    let loader = Loader::new().with_default_tls_resolver();
    let provider = Relocator::new()
        .run(
            loader
                .load_dylib(ElfBinary::new("provider.so", &provider.data))
                .expect("failed to load TLS provider"),
        )
        .relocate()
        .expect("failed to relocate TLS provider");
    let consumer = Relocator::new()
        .run(
            loader
                .load_dylib(ElfBinary::new("consumer.so", &output.data))
                .expect("failed to load TLS consumer"),
        )
        .modules([&provider])
        .relocate()
        .expect("failed to relocate TLS consumer");

    TlsScenario {
        output,
        provider,
        consumer,
    }
}
