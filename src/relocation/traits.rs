use super::{SymDef, find_symdef_impl};
use crate::{
    Result,
    elf::ElfRelType,
    image::{ElfCore, LoadedCore},
    sync::Arc,
};
use alloc::{boxed::Box, vec::Vec};
#[cfg(not(feature = "lazy-binding"))]
use core::marker::PhantomData;

/// A trait for looking up external symbols during relocation.
///
/// Implement this trait when the default relocation scope is not enough and you need
/// to supply addresses from the host process, an embedding runtime, or another
/// custom symbol source.
///
/// Closures of type `Fn(&str) -> Option<*const ()>` implement this trait automatically.
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
    /// Finds the address of a symbol by its name, returning `None` if not found.
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

/// A trait for intercepting relocations during relocation.
///
/// Implement this to override specific relocations, record relocation activity,
/// or provide custom handling before or after the default relocation logic runs.
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

/// Context passed to [`RelocationHandler::handle`].
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

/// A marker trait for objects that support lazy binding.
pub trait SupportLazy {}

/// Binding strategy configuration for relocation.
///
/// This controls whether the loader follows the ELF object's default binding mode,
/// forces eager binding, or forces lazy binding when that feature is enabled.
pub enum BindingOptions<S = ()> {
    /// Follow the ELF object's default binding behavior.
    Default,
    /// Force eager binding.
    Eager,
    /// Force lazy binding with an optional custom symbol lookup scope.
    #[cfg(feature = "lazy-binding")]
    Lazy { scope: Option<S> },
    #[cfg(not(feature = "lazy-binding"))]
    #[doc(hidden)]
    __Marker(PhantomData<fn() -> S>),
}

impl<S> Default for BindingOptions<S> {
    fn default() -> Self {
        Self::Default
    }
}

impl BindingOptions<()> {
    /// Creates the default binding mode.
    ///
    /// This is mainly useful in generic builder chains where
    /// `BindingOptions::Default` would require explicit type annotations.
    pub const fn default_mode() -> Self {
        Self::Default
    }

    /// Creates an eager binding configuration.
    pub const fn eager() -> Self {
        Self::Eager
    }

    /// Creates a lazy binding configuration without a custom scope.
    #[cfg(feature = "lazy-binding")]
    pub const fn lazy() -> Self {
        Self::Lazy { scope: None }
    }

    /// Creates a lazy binding configuration with a custom scope.
    #[cfg(feature = "lazy-binding")]
    pub fn lazy_with_scope<S>(scope: S) -> BindingOptions<S> {
        BindingOptions::Lazy { scope: Some(scope) }
    }
}

/// A trait for raw image types that can undergo relocation.
///
/// In normal use, callers do not invoke this trait directly. Instead, they load a raw
/// image with [`crate::Loader`] and then call `.relocator().relocate()`.
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
    /// * `binding` - Binding strategy configuration.
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
        binding: BindingOptions<LazyS>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized;
}
