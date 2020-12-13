//! This crate defines a set of traits which describe the functionality of
//! [block ciphers][1] and [stream ciphers][2].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Stream_cipher

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "block-mode")]
pub extern crate block_padding;
#[cfg(feature = "dev")]
pub extern crate blobby;

pub mod errors;
#[cfg(feature = "dev")]
mod dev;
mod block;
mod common;
#[cfg(feature = "block-padding")]
mod mode;
mod stream;

pub use crate::{
    block::*,
    common::*,
    stream::*,
};
#[cfg(feature = "block-mode")]
pub use crate::mode::BlockModeCore;
pub use generic_array::{self, typenum::consts};
