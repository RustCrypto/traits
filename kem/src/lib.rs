#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/kem"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications)]

#[cfg(feature = "std")]
extern crate std;

mod errors;
mod kem;

pub use crate::{errors::*, kem::*};
pub use generic_array;
