//! Facade crate for [RustCrypto Traits][1], providing a single place to
//! access compatible versions of all traits from the Rust Crypto project.
//!
//! # About
//!
//! The [RustCrypto Project][2] publishes and maintains independently versioned
//! crates containing traits for many different kinds of cryptographic
//! algorithms.
//!
//! However, these algorithms are often interdependent (e.g. many depend on digest
//! algorithms), which requires figuring out which versions of the trait crates
//! are compatible with each other.
//!
//! This crate will automatically pull in compatible versions of these crates,
//! with each one gated under a cargo feature, providing a single place to both
//! import and upgrade these crates while ensuring they remain compatible.
//!
//! # Traits
//!
//! - [`aead`] - Authenticated Encryption with Associated Data
//!   (i.e. high-level symmetric encryption)
//! - [`block_cipher`] - block-based cryptographic permutations
//!   (i.e. low-level symmetric encryption)
//! - [`mac`] - message authentication codes (i.e. symmetric message
//!   authentication)
//! - [`digest`] - cryptographic hash functions
//! - [`signature`] - digital signatures (i.e. public key-based message
//!   authentication)
//! - [`stream_cipher`] - ciphers based on randomly generated keystreams
//!   (i.e. low-level symmetric encryption)
//! - [`universal_hash`] - universal hash functions (used to build MACs)
//!
//! [1]: https://github.com/RustCrypto/traits
//! [2]: https://github.com/RustCrypto
//!
//! [`aead`]: https://docs.rs/aead
//! [`block_cipher`]: https://docs.rs/block-cipher
//! [`mac`]: https://docs.rs/crypto-mac
//! [`digest`]: https://docs.rs/digest
//! [`signature`]: https://docs.rs/signature
//! [`stream_cipher`]: https://docs.rs/stream-cipher
//! [`universal_hash`]: https://docs.rs/universal-hash

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

#[cfg(feature = "aead")]
pub use aead;

#[cfg(feature = "block-cipher")]
pub use block_cipher;

#[cfg(feature = "crypto-mac")]
pub use crypto_mac as mac;

#[cfg(feature = "digest")]
pub use digest;

#[cfg(feature = "signature")]
pub use signature;

#[cfg(feature = "stream-cipher")]
pub use stream_cipher;

#[cfg(feature = "universal-hash")]
pub use universal_hash;
