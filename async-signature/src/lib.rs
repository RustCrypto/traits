#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_qualifications,
    missing_debug_implementations
)]

pub mod hazmat;

pub use signature::{self, Error};

#[cfg(feature = "digest")]
pub use signature::digest::{self, Digest};

#[deprecated(since = "0.6.0", note = "use `signature::AsyncSigner` instead")]
pub use signature::AsyncSigner;

#[cfg(feature = "digest")]
#[deprecated(since = "0.6.0", note = "use `signature::AsyncDigestSigner` instead")]
pub use signature::AsyncDigestSigner;

#[cfg(feature = "rand_core")]
#[deprecated(
    since = "0.6.0",
    note = "use `signature::AsyncRandomizedSigner` instead"
)]
pub use signature::AsyncRandomizedSigner;
