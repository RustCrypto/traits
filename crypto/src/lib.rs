#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

pub use crypto_common as common;

#[cfg(feature = "aead")]
pub use aead;

#[cfg(feature = "cipher")]
pub use cipher;

#[cfg(feature = "digest")]
pub use digest;

#[cfg(feature = "elliptic-curve")]
pub use elliptic_curve;

#[cfg(feature = "password-hash")]
pub use password_hash;

#[cfg(feature = "signature")]
pub use signature;

#[cfg(feature = "universal-hash")]
pub use universal_hash;
