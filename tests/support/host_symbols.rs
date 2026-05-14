#![allow(dead_code)]

use std::collections::HashMap;

use elf_loader::image::{SyntheticModule, SyntheticSymbol};

pub(crate) const EXTERNAL_FUNC_NAME: &str = "external_func";
pub(crate) const EXTERNAL_FUNC_NAME2: &str = "external_func2";
pub(crate) const EXTERNAL_VAR_NAME: &str = "external_var";
pub(crate) const EXTERNAL_TLS_NAME: &str = "external_tls";
pub(crate) const EXTERNAL_TLS_NAME2: &str = "external_tls2";
pub(crate) const COPY_VAR_NAME: &str = "copy_var";
pub(crate) const LOCAL_VAR_NAME: &str = "local_var";

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct F64Pair(pub(crate) [f64; 2]);

#[unsafe(no_mangle)]
extern "C" fn external_func(
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
    a6: i64,
    a7: i64,
    a8: i64,
    vector: F64Pair,
    f1: f64,
    f2: f64,
    f3: f64,
    f4: f64,
    f5: f64,
    f6: f64,
    f7: f64,
) -> f64 {
    (a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8) as f64
        + (f1 + f2 + f3 + f4 + f5 + f6 + f7)
        + vector.0[0]
        + vector.0[1]
}

static mut EXTERNAL_VAR: i32 = 100;

pub(crate) struct TestHostSymbols {
    pub(crate) addresses: HashMap<&'static str, usize>,
}

impl TestHostSymbols {
    pub(crate) fn new() -> Self {
        let addresses = HashMap::from([
            (EXTERNAL_FUNC_NAME, external_func as *const () as usize),
            (EXTERNAL_FUNC_NAME2, external_func as *const () as usize),
            (EXTERNAL_VAR_NAME, &raw const EXTERNAL_VAR as usize),
        ]);

        Self { addresses }
    }

    pub(crate) fn source(&self, name: impl Into<String>) -> SyntheticModule {
        let mut source = SyntheticModule::empty(name);
        for (&symbol_name, &address) in self.addresses.iter() {
            let symbol = match symbol_name {
                EXTERNAL_FUNC_NAME | EXTERNAL_FUNC_NAME2 => {
                    SyntheticSymbol::function(symbol_name, address as *const ())
                }
                _ => SyntheticSymbol::object(symbol_name, address as *const (), 0),
            };
            source.insert(symbol);
        }
        source
    }
}
