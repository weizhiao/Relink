use core::{marker::PhantomData, ops::Deref};

use super::LoadedCore;
use crate::{
    elf::SymbolInfo,
    relocation::{RelocationArch, SymDef},
};

/// A typed symbol retrieved from a loaded ELF module.
///
/// `Symbol` provides safe access to a function or variable within a loaded library.
/// It carries a lifetime marker `'lib` to ensure that the symbol cannot outlive
/// the library it was loaded from, preventing use-after-free errors.
#[derive(Debug, Clone)]
pub struct Symbol<'lib, T: 'lib> {
    /// Raw pointer to the symbol's memory location.
    pub(crate) ptr: *mut (),

    /// Phantom data to bind the symbol's lifetime to the source library.
    pub(crate) pd: PhantomData<&'lib T>,
}

impl<'lib, T> Deref for Symbol<'lib, T> {
    type Target = T;

    /// Accesses the underlying symbol as a reference to type `T`.
    ///
    /// This allows calling functions or accessing variables directly.
    fn deref(&self) -> &T {
        unsafe { &*(&self.ptr as *const *mut _ as *const T) }
    }
}

impl<'lib, T> Symbol<'lib, T> {
    /// Consumes the `Symbol` and returns its raw memory address.
    ///
    /// # Returns
    /// A raw pointer to the symbol data.
    pub fn into_raw(self) -> *const () {
        self.ptr
    }
}

impl<D: 'static, Arch: RelocationArch> LoadedCore<D, Arch> {
    /// Gets a pointer to a function or static variable by symbol name
    ///
    /// The symbol is interpreted as-is; no mangling is done. This means
    /// that symbols like `x::y` are most likely invalid.
    ///
    /// # Safety
    /// Users of this API must specify the correct type of the function
    /// or variable loaded.
    ///
    /// # Examples
    /// ```no_run
    /// # use elf_loader::{input::ElfBinary, image::Symbol, Loader};
    /// # let mut loader = Loader::new();
    /// # let lib = loader
    /// #     .load_dylib(ElfBinary::new("target/liba.so", &[]))
    /// #        .unwrap().relocator().relocate().unwrap();
    /// unsafe {
    ///     let awesome_function = lib.get::<unsafe extern "C" fn(f64) -> f64>("awesome_function").unwrap();
    ///     awesome_function(0.42);
    /// }
    /// ```
    ///
    /// A static variable may also be loaded and inspected:
    /// ```no_run
    /// # use elf_loader::{input::ElfBinary, image::Symbol, Loader};
    /// # let mut loader = Loader::new();
    /// # let lib = loader
    /// #     .load_dylib(ElfBinary::new("target/liba.so", &[]))
    /// #        .unwrap().relocator().relocate().unwrap();
    /// unsafe {
    ///     let awesome_variable = lib.get::<*mut f64>("awesome_variable").unwrap();
    ///     **awesome_variable = 42.0;
    /// };
    /// ```
    ///
    /// # Arguments
    /// * `name` - The name of the symbol to look up
    ///
    /// # Returns
    /// * `Some(symbol)` - If the symbol is found
    /// * `None` - If the symbol is not found
    #[inline]
    pub unsafe fn get<'lib, T>(&'lib self, name: &str) -> Option<Symbol<'lib, T>> {
        let syminfo = SymbolInfo::from_str(name, None);
        let mut precompute = syminfo.precompute();
        self.symtab()
            .lookup_filter(&syminfo, &mut precompute)
            .map(|sym| Symbol {
                ptr: SymDef::<D, Arch>::new(Some(sym), unsafe { self.core_ref() })
                    .convert()
                    .as_mut_ptr(),
                pd: PhantomData,
            })
    }

    /// Load a versioned symbol from the ELF object
    ///
    /// # Safety
    /// Users of this API must specify the correct type of the function
    /// or variable loaded.
    ///
    /// # Examples
    /// ```no_run
    /// # use elf_loader::{Loader, input::ElfFile};
    /// # let mut loader = Loader::new();
    /// # let lib = loader
    /// #     .load_dylib(ElfFile::from_path("target/liba.so").unwrap())
    /// #        .unwrap().relocator().relocate().unwrap();;
    /// let symbol = unsafe { lib.get_version::<fn()>("function_name", "1.0").unwrap() };
    /// ```
    ///
    /// # Arguments
    /// * `name` - The name of the symbol to look up
    /// * `version` - The version of the symbol to look up
    ///
    /// # Returns
    /// * `Some(symbol)` - If the symbol is found
    /// * `None` - If the symbol is not found
    #[cfg(feature = "version")]
    #[inline]
    pub unsafe fn get_version<'lib, T>(
        &'lib self,
        name: &str,
        version: &str,
    ) -> Option<Symbol<'lib, T>> {
        let syminfo = SymbolInfo::from_str(name, Some(version));
        let mut precompute = syminfo.precompute();
        self.symtab()
            .lookup_filter(&syminfo, &mut precompute)
            .map(|sym| Symbol {
                ptr: SymDef::<D, Arch>::new(Some(sym), unsafe { self.core_ref() })
                    .convert()
                    .as_mut_ptr(),
                pd: PhantomData,
            })
    }
}

// Safety: Symbol can be sent between threads if T can
unsafe impl<T: Send> Send for Symbol<'_, T> {}

// Safety: Symbol can be shared between threads if T can
unsafe impl<T: Sync> Sync for Symbol<'_, T> {}
