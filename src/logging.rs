#[cfg(feature = "log")]
macro_rules! trace {
    ($($arg:tt)*) => {{
        ::log::trace!($($arg)*);
    }};
}

#[cfg(not(feature = "log"))]
macro_rules! trace {
    ($($arg:tt)*) => {{
        if false {
            let _ = ::core::format_args!($($arg)*);
        }
    }};
}

pub(crate) use trace;

#[cfg(feature = "log")]
macro_rules! debug {
    ($($arg:tt)*) => {{
        ::log::debug!($($arg)*);
    }};
}

#[cfg(not(feature = "log"))]
macro_rules! debug {
    ($($arg:tt)*) => {{
        if false {
            let _ = ::core::format_args!($($arg)*);
        }
    }};
}

pub(crate) use debug;

#[cfg(feature = "log")]
macro_rules! info {
    ($($arg:tt)*) => {{
        ::log::info!($($arg)*);
    }};
}

#[cfg(not(feature = "log"))]
macro_rules! info {
    ($($arg:tt)*) => {{
        if false {
            let _ = ::core::format_args!($($arg)*);
        }
    }};
}

pub(crate) use info;

#[cfg(feature = "log")]
macro_rules! error {
    ($($arg:tt)*) => {{
        ::log::error!($($arg)*);
    }};
}

#[cfg(not(feature = "log"))]
macro_rules! error {
    ($($arg:tt)*) => {{
        if false {
            let _ = ::core::format_args!($($arg)*);
        }
    }};
}

pub(crate) use error;
