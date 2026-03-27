#![allow(unused_imports)]
#![allow(dead_code)]

mod assertions;
mod fixture;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindingKind {
    Eager,
    #[cfg(feature = "lazy-binding")]
    Lazy,
}

impl BindingKind {
    pub(crate) const fn is_lazy(self) -> bool {
        match self {
            Self::Eager => false,
            #[cfg(feature = "lazy-binding")]
            Self::Lazy => true,
        }
    }
}

pub(crate) use fixture::BindingFixture;
