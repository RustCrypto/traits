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

pub mod block;
pub mod common;
pub mod errors;
#[cfg(feature = "block-padding")]
pub mod mode;
pub mod stream;

pub use crate::{
    block::{
        BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, NewBlockCipher,
    },
    common::{NewCipher, FromBlockCipher},
    stream::{AsyncStreamCipher, StreamCipher, StreamCipherSeek},
};
#[cfg(feature = "block-mode")]
pub use crate::mode::{BlockModeCore};
pub use generic_array::{self, typenum::consts};
