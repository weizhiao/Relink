use crate::const_builder::NoDrop;
use core::{mem::MaybeUninit, ptr};

/// Reusable relocation configuration.
///
/// A `Relocator` stores the stable parts of relocation policy: relocation
/// handlers and lazy binder. Attach a raw image with
/// [`Relocator::run`] to create a [`RelocatorRun`] that owns per-run state such
/// as the object, observer, and symbol scope.
pub struct Relocator<PreH = (), PostH = (), Binder = ()> {
    pub(super) pre_handler: PreH,
    pub(super) post_handler: PostH,
    pub(super) lazy_binder: Binder,
}

struct RelocatorFields<PreH, PostH, Binder> {
    pre_handler: NoDrop<PreH>,
    post_handler: NoDrop<PostH>,
    lazy_binder: NoDrop<Binder>,
}

impl<PreH, PostH, Binder> Clone for Relocator<PreH, PostH, Binder>
where
    PreH: Clone,
    PostH: Clone,
    Binder: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            pre_handler: self.pre_handler.clone(),
            post_handler: self.post_handler.clone(),
            lazy_binder: self.lazy_binder.clone(),
        }
    }
}

impl Relocator<(), (), ()> {
    /// Creates a new empty relocation configuration.
    #[inline]
    pub const fn new() -> Self {
        Self {
            pre_handler: (),
            post_handler: (),
            lazy_binder: (),
        }
    }
}

impl Default for Relocator<(), (), ()> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<PreH, PostH, Binder> Relocator<PreH, PostH, Binder> {
    #[inline]
    const fn into_fields(self) -> RelocatorFields<PreH, PostH, Binder> {
        let this = MaybeUninit::new(self);
        let this = this.as_ptr();

        // SAFETY: `this` points at the fully initialized `self` stored inside
        // `MaybeUninit`, so every field read below is initialized and aligned.
        // Discarded fields are only discarded by const builders under a `Copy`
        // bound, so bypassing their destructor cannot skip meaningful cleanup.
        unsafe {
            RelocatorFields {
                pre_handler: NoDrop::read(ptr::addr_of!((*this).pre_handler)),
                post_handler: NoDrop::read(ptr::addr_of!((*this).post_handler)),
                lazy_binder: NoDrop::read(ptr::addr_of!((*this).lazy_binder)),
            }
        }
    }

    /// Sets the relocation handler that runs before the built-in logic.
    pub const fn pre_handler<NewPreH>(self, handler: NewPreH) -> Relocator<NewPreH, PostH, Binder>
    where
        PreH: Copy,
    {
        let RelocatorFields {
            post_handler,
            lazy_binder,
            ..
        } = self.into_fields();

        Relocator {
            pre_handler: handler,
            post_handler: post_handler.into_inner(),
            lazy_binder: lazy_binder.into_inner(),
        }
    }

    /// Sets the relocation handler that runs after the built-in logic.
    pub const fn post_handler<NewPostH>(
        self,
        handler: NewPostH,
    ) -> Relocator<PreH, NewPostH, Binder>
    where
        PostH: Copy,
    {
        let RelocatorFields {
            pre_handler,
            lazy_binder,
            ..
        } = self.into_fields();

        Relocator {
            pre_handler: pre_handler.into_inner(),
            post_handler: handler,
            lazy_binder: lazy_binder.into_inner(),
        }
    }

    /// Overrides the lazy PLT binder used to prepare runtime binding.
    pub const fn lazy_binder<NewBinder>(
        self,
        binder: NewBinder,
    ) -> Relocator<PreH, PostH, NewBinder>
    where
        Binder: Copy,
    {
        let RelocatorFields {
            pre_handler,
            post_handler,
            ..
        } = self.into_fields();

        Relocator {
            pre_handler: pre_handler.into_inner(),
            post_handler: post_handler.into_inner(),
            lazy_binder: binder,
        }
    }
}
