#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications, missing_debug_implementations)]

/// Use the KDF to derive the given amount of output.
pub trait Derive {
    /// Consumes the KDF instance and derives as much data as will fit in `out`,
    /// overwriting its contents.
    fn derive(self, out: &mut [u8]);
}
