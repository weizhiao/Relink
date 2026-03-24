use core::{marker::PhantomData, ops::Deref};

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

// Safety: Symbol can be sent between threads if T can
unsafe impl<T: Send> Send for Symbol<'_, T> {}

// Safety: Symbol can be shared between threads if T can
unsafe impl<T: Sync> Sync for Symbol<'_, T> {}
