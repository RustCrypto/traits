//! This crate defines a set of traits which describe the functionality of
//! [block ciphers][1], [block modes][2], and [stream ciphers][3].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
//! [3]: https://en.wikipedia.org/wiki/Stream_cipher

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use crypto_common;
pub use inout;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "dev")]
pub use blobby;

pub use block_buffer;

mod block;
#[cfg(feature = "dev")]
mod dev;
mod errors;
mod stream;
mod stream_core;
mod stream_wrapper;

pub use crate::{block::*, errors::*, stream::*, stream_core::*, stream_wrapper::*};
pub use crypto_common::{
    Block, InnerIvInit, InvalidLength, Iv, IvSizeUser, Key, KeyInit, KeyIvInit, KeySizeUser,
};
pub use generic_array::{self, typenum::consts};

/// Trait for loading current IV state.
pub trait IvState: IvSizeUser {
    /// Returns current IV state.
    fn iv_state(&self) -> Iv<Self>;
}
