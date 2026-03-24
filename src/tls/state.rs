#[cfg(feature = "tls")]
mod enabled {
    use crate::tls::TlsDescDynamicArg;
    use alloc::{boxed::Box, vec::Vec};

    #[derive(Default)]
    pub(crate) struct TlsDescArgs(Vec<Box<TlsDescDynamicArg>>);

    impl TlsDescArgs {
        pub(crate) fn push(&mut self, arg: Box<TlsDescDynamicArg>) {
            self.0.push(arg);
        }
    }

    /// TLS runtime state attached to a loaded ELF core.
    ///
    /// This keeps TLS-specific bookkeeping out of `CoreInner`, so TLS state can
    /// collapse to an empty implementation when the `tls` feature is disabled.
    pub(crate) struct CoreTlsState {
        mod_id: Option<usize>,
        tp_offset: Option<isize>,
        unregister: fn(usize),
        desc_args: Box<[Box<TlsDescDynamicArg>]>,
    }

    impl CoreTlsState {
        pub(crate) fn new(
            mod_id: Option<usize>,
            tp_offset: Option<isize>,
            unregister: fn(usize),
        ) -> Self {
            Self {
                mod_id,
                tp_offset,
                unregister,
                desc_args: Box::new([]),
            }
        }

        #[inline]
        pub(crate) fn mod_id(&self) -> Option<usize> {
            self.mod_id
        }

        #[inline]
        pub(crate) fn tp_offset(&self) -> Option<isize> {
            self.tp_offset
        }

        #[inline]
        pub(crate) fn cleanup(&self) {
            if let Some(mod_id) = self.mod_id {
                (self.unregister)(mod_id);
            }
        }

        pub(crate) fn set_desc_args(&mut self, args: TlsDescArgs) {
            self.desc_args = args.0.into_boxed_slice();
        }
    }

    pub(crate) use CoreTlsState as State;
    pub(crate) use TlsDescArgs as DescArgs;
}

#[cfg(not(feature = "tls"))]
mod disabled {
    #[derive(Default)]
    pub(crate) struct TlsDescArgs;

    /// TLS runtime state attached to a loaded ELF core.
    ///
    /// This keeps TLS-specific bookkeeping out of `CoreInner`, so TLS state can
    /// collapse to an empty implementation when the `tls` feature is disabled.
    pub(crate) struct CoreTlsState;

    impl CoreTlsState {
        pub(crate) fn new(
            _mod_id: Option<usize>,
            _tp_offset: Option<isize>,
            _unregister: fn(usize),
        ) -> Self {
            Self
        }

        #[inline]
        pub(crate) fn mod_id(&self) -> Option<usize> {
            None
        }

        #[inline]
        pub(crate) fn tp_offset(&self) -> Option<isize> {
            None
        }

        #[inline]
        pub(crate) fn cleanup(&self) {}

        pub(crate) fn set_desc_args(&mut self, _args: TlsDescArgs) {}
    }

    pub(crate) use CoreTlsState as State;
    pub(crate) use TlsDescArgs as DescArgs;
}

#[cfg(feature = "tls")]
pub(crate) use enabled::{DescArgs as TlsDescArgs, State as CoreTlsState};

#[cfg(not(feature = "tls"))]
pub(crate) use disabled::{DescArgs as TlsDescArgs, State as CoreTlsState};
