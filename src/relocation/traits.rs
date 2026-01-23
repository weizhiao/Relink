use super::{SymDef, find_symdef_impl};
use crate::{
    Result,
    elf::ElfRelType,
    image::{ElfCore, LoadedCore},
};
use alloc::{boxed::Box, vec::Vec};

#[cfg(not(feature = "portable-atomic"))]
use alloc::sync::Arc;
#[cfg(feature = "portable-atomic")]
use portable_atomic_util::Arc;

/// A trait for looking up symbols during relocation.
///
/// Implement this trait to provide custom symbol resolution strategies.
/// The relocator will use this to find addresses of external symbols that
/// the ELF object depends on.
///
/// # Examples
///
/// Using a closure for simple lookups:
/// ```rust
/// use elf_loader::relocation::SymbolLookup;
///
/// let lookup = |name: &str| {
///     match name {
///         "malloc" => Some(0x1234 as *const ()),
///         "free" => Some(0x5678 as *const ()),
///         _ => None,
///     }
/// };
/// ```
///
/// Using a struct for complex resolution:
/// ```rust
/// use elf_loader::relocation::SymbolLookup;
/// use std::collections::HashMap;
///
/// struct SymbolResolver {
///     symbols: HashMap<String, *const ()>,
/// }
///
/// impl SymbolLookup for SymbolResolver {
///     fn lookup(&self, name: &str) -> Option<*const ()> {
///         self.symbols.get(name).copied()
///     }
/// }
/// ```
pub trait SymbolLookup {
    /// Finds the address of a symbol by its name.
    ///
    /// # Arguments
    /// * `name` - The symbol name to resolve.
    ///
    /// # Returns
    /// * `Some(ptr)` - The symbol's address if found.
    /// * `None` - Symbol not found.
    fn lookup(&self, name: &str) -> Option<*const ()>;
}

impl<F: ?Sized> SymbolLookup for F
where
    F: Fn(&str) -> Option<*const ()>,
{
    fn lookup(&self, name: &str) -> Option<*const ()> {
        self(name)
    }
}

impl<S: SymbolLookup + ?Sized> SymbolLookup for Arc<S> {
    fn lookup(&self, name: &str) -> Option<*const ()> {
        (**self).lookup(name)
    }
}

impl<S: SymbolLookup + ?Sized> SymbolLookup for &Arc<S> {
    fn lookup(&self, name: &str) -> Option<*const ()> {
        (**self).lookup(name)
    }
}

impl SymbolLookup for () {
    fn lookup(&self, _name: &str) -> Option<*const ()> {
        None
    }
}

/// A trait for handling unknown or custom relocations.
///
/// Implement this to provide custom logic for relocations not handled by default,
/// or to intercept and modify standard relocations.
///
/// # Examples
///
/// ```rust
/// use elf_loader::relocation::{RelocationHandler, RelocationContext};
/// use elf_loader::Result;
///
/// struct CustomHandler;
///
/// impl RelocationHandler for CustomHandler {
///     fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Option<Result<Option<usize>>> {
///         let rel = ctx.rel();
///         // Handle specific relocation types
///         match rel.r_type() {
///             0x1234 => {
///                 // Custom relocation logic
///                 Some(Ok(None)) // Handled successfully
///             }
///             _ => None, // Fall through to default
///         }
///     }
/// }
/// ```
pub trait RelocationHandler {
    /// Handles a relocation.
    ///
    /// # Arguments
    /// * `ctx` - Context containing relocation details and scope.
    ///
    /// # Returns
    /// * `Some(Ok(None))` - Handled successfully, no library dependency.
    /// * `Some(Ok(Some(idx)))` - Handled successfully, used library at `scope[idx]`.
    /// * `Some(Err(e))` - Handled but failed with error.
    /// * `None` - Not handled, fall through to default behavior.
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Option<Result<Option<usize>>>;
}

/// Context passed to `RelocationHandler::handle` containing relocation details.
///
/// This struct provides access to the relocation entry, the module being relocated,
/// and the current symbol resolution scope.
pub struct RelocationContext<'a, D> {
    rel: &'a ElfRelType,
    lib: &'a ElfCore<D>,
    scope: &'a [LoadedCore<D>],
}

impl<'a, D> RelocationContext<'a, D> {
    /// Construct a new `RelocationContext`.
    #[inline]
    pub(crate) fn new(
        rel: &'a ElfRelType,
        lib: &'a ElfCore<D>,
        scope: &'a [LoadedCore<D>],
    ) -> Self {
        Self { rel, lib, scope }
    }

    /// Access the relocation entry.
    #[inline]
    pub fn rel(&self) -> &ElfRelType {
        self.rel
    }

    /// Access the core component where the relocation appears.
    #[inline]
    pub fn lib(&self) -> &ElfCore<D> {
        self.lib
    }

    /// Access the current resolution scope.
    #[inline]
    pub fn scope(&self) -> &[LoadedCore<D>] {
        self.scope
    }

    /// Find symbol definition in the current scope
    #[inline]
    pub fn find_symdef(&self, r_sym: usize) -> Option<(SymDef<'a, D>, Option<usize>)> {
        let symbol = self.lib.symtab();
        let (sym, syminfo) = symbol.symbol_idx(r_sym);
        find_symdef_impl(self.lib, self.scope, sym, &syminfo)
    }
}

impl RelocationHandler for () {
    fn handle<D>(&self, _ctx: &RelocationContext<'_, D>) -> Option<Result<Option<usize>>> {
        None
    }
}

impl<H: RelocationHandler + ?Sized> RelocationHandler for &H {
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Option<Result<Option<usize>>> {
        (**self).handle(ctx)
    }
}

impl<H: RelocationHandler + ?Sized> RelocationHandler for &mut H {
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Option<Result<Option<usize>>> {
        (**self).handle(ctx)
    }
}

impl<H: RelocationHandler + ?Sized> RelocationHandler for Box<H> {
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Option<Result<Option<usize>>> {
        (**self).handle(ctx)
    }
}

impl<H: RelocationHandler + ?Sized> RelocationHandler for Arc<H> {
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Option<Result<Option<usize>>> {
        (**self).handle(ctx)
    }
}

/// A trait for objects that can be relocated.
///
/// Types implementing this trait can undergo symbol resolution and address fixup.
/// The relocation process resolves external symbol references and applies necessary
/// address adjustments to make the object executable.
pub trait Relocatable<D = ()>: Sized {
    /// The type of the relocated object.
    type Output;

    /// Execute the relocation process with the given configuration.
    ///
    /// # Arguments
    /// * `scope` - Loaded modules available for symbol resolution.
    /// * `pre_find` - Primary symbol lookup strategy.
    /// * `post_find` - Fallback symbol lookup strategy.
    /// * `pre_handler` - Handler called before default relocation logic.
    /// * `post_handler` - Handler called after default logic if not handled.
    /// * `lazy` - Whether to enable lazy binding.
    /// * `lazy_scope` - Symbol lookup for lazy binding.
    ///
    /// # Returns
    /// The relocated object on success.
    fn relocate<PreS, PostS, LazyS, PreH, PostH>(
        self,
        scope: Vec<LoadedCore<D>>,
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
        lazy: Option<bool>,
        lazy_scope: Option<LazyS>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized;
}
