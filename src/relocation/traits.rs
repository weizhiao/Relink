use super::{SymDef, find_symdef_impl};
use crate::{
    Result,
    elf::ElfRelType,
    image::{ElfCore, LoadedCore},
    sync::Arc,
};
use alloc::boxed::Box;

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
/// use elf_loader::elf::ElfRelocationType;
/// use elf_loader::relocation::{HandleResult, RelocationContext, RelocationHandler};
/// use elf_loader::Result;
///
/// struct CustomHandler;
///
/// impl RelocationHandler for CustomHandler {
///     fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Result<HandleResult> {
///         let rel = ctx.rel();
///         // Handle specific relocation types
///         match rel.r_type() {
///             value if value == ElfRelocationType::new(0x1234) => {
///                 // Custom relocation logic
///                 Ok(HandleResult::Handled)
///             }
///             _ => Ok(HandleResult::Unhandled), // Fall through to default
///         }
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleResult {
    /// The handler did not process this relocation.
    Unhandled,
    /// The handler processed this relocation.
    Handled,
}

impl HandleResult {
    #[inline]
    pub const fn is_unhandled(self) -> bool {
        matches!(self, Self::Unhandled)
    }
}

pub trait RelocationHandler {
    /// Handles a relocation.
    ///
    /// # Arguments
    /// * `ctx` - Context containing relocation details and scope.
    ///
    /// # Returns
    /// * `Ok(HandleResult::Unhandled)` - Not handled, fall through to default behavior.
    /// * `Ok(HandleResult::Handled)` - Handled successfully.
    /// * `Err(e)` - The handler failed.
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Result<HandleResult>;
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
    pub fn find_symdef(&self, r_sym: usize) -> Option<SymDef<'a, D>> {
        let symbol = self.lib.symtab();
        let (sym, syminfo) = symbol.symbol_idx(r_sym);
        find_symdef_impl(self.lib, self.scope, sym, &syminfo)
    }
}

impl RelocationHandler for () {
    fn handle<D>(&self, _ctx: &RelocationContext<'_, D>) -> Result<HandleResult> {
        Ok(HandleResult::Unhandled)
    }
}

impl<H: RelocationHandler + ?Sized> RelocationHandler for &H {
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

impl<H: RelocationHandler + ?Sized> RelocationHandler for &mut H {
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

impl<H: RelocationHandler + ?Sized> RelocationHandler for Box<H> {
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

impl<H: RelocationHandler + ?Sized> RelocationHandler for Arc<H> {
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

/// Binding mode configuration for relocation.
///
/// This controls whether the loader follows the ELF object's default binding mode
/// or overrides it when lazy binding support is enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BindingMode {
    /// Follow the ELF object's default binding behavior.
    #[default]
    Default,
    /// Force eager binding.
    Eager,
    /// Force lazy binding.
    Lazy,
}

/// Relocation-time symbol lookup hooks.
pub(crate) struct LookupHooks<'a, PreS: ?Sized, PostS: ?Sized> {
    pub(crate) pre_find: &'a PreS,
    pub(crate) post_find: &'a PostS,
}

impl<'a, PreS: ?Sized, PostS: ?Sized> LookupHooks<'a, PreS, PostS> {
    #[inline]
    pub(crate) const fn new(pre_find: &'a PreS, post_find: &'a PostS) -> Self {
        Self {
            pre_find,
            post_find,
        }
    }
}

/// Lazy-fixup symbol lookup hooks.
pub(crate) struct LazyLookupHooks<LazyPreS, LazyPostS> {
    pub(crate) pre_find: LazyPreS,
    pub(crate) post_find: LazyPostS,
}

impl<LazyPreS, LazyPostS> LazyLookupHooks<LazyPreS, LazyPostS> {
    #[inline]
    pub(crate) const fn new(pre_find: LazyPreS, post_find: LazyPostS) -> Self {
        Self {
            pre_find,
            post_find,
        }
    }
}

/// Relocation handlers that run before and after the built-in relocation logic.
pub(crate) struct HandlerHooks<'a, PreH: ?Sized, PostH: ?Sized> {
    pub(crate) pre: &'a PreH,
    pub(crate) post: &'a PostH,
}

impl<'a, PreH: ?Sized, PostH: ?Sized> HandlerHooks<'a, PreH, PostH> {
    #[inline]
    pub(crate) const fn new(pre: &'a PreH, post: &'a PostH) -> Self {
        Self { pre, post }
    }
}

/// Internal relocation configuration shared across raw image types.
pub struct RelocateArgs<
    'a,
    D,
    PreS: ?Sized,
    PostS: ?Sized,
    LazyPreS,
    LazyPostS,
    PreH: ?Sized,
    PostH: ?Sized,
> {
    pub(crate) scope: Arc<[LoadedCore<D>]>,
    pub(crate) binding: BindingMode,
    pub(crate) lookup: LookupHooks<'a, PreS, PostS>,
    pub(crate) lazy_lookup: LazyLookupHooks<LazyPreS, LazyPostS>,
    pub(crate) handlers: HandlerHooks<'a, PreH, PostH>,
}

impl<'a, D, PreS: ?Sized, PostS: ?Sized, LazyPreS, LazyPostS, PreH: ?Sized, PostH: ?Sized>
    RelocateArgs<'a, D, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>
{
    #[inline]
    pub(crate) fn new(
        scope: Arc<[LoadedCore<D>]>,
        binding: BindingMode,
        lookup: LookupHooks<'a, PreS, PostS>,
        lazy_lookup: LazyLookupHooks<LazyPreS, LazyPostS>,
        handlers: HandlerHooks<'a, PreH, PostH>,
    ) -> Self {
        Self {
            scope,
            binding,
            lookup,
            lazy_lookup,
            handlers,
        }
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
    /// * `args` - Scope, lookup hooks, handlers, and binding mode configuration.
    ///
    /// # Returns
    /// The relocated object on success.
    fn relocate<PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>,
    ) -> Result<Self::Output>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyPreS: SymbolLookup + Send + Sync + 'static,
        LazyPostS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized;
}

/// Marker trait for raw image types that support lazy-binding fixup hooks.
pub trait SupportLazy {}

impl SupportLazy for () {}
