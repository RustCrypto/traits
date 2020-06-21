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
//! # Trait re-exports
//!
//! Below are the re-exports of the various RustCrypto crates available through
//! this crate's facade. To access a particular re-export you (or a crate you
//! depend on) must enable the associated Cargo feature named below.
//!
//! | Module name | Cargo feature | Description |
//! |-------------|---------------|-------------|
//! | [`aead`](https://docs.rs/aead) | `aead` | Authenticated Encryption with Associated Data (i.e. high-level symmetric encryption) |
//! | [`block_cipher`](https://docs.rs/block-cipher) | `block-cipher` | Block-based cryptographic permutations (i.e. low-level symmetric encryption) |
//! | [`digest`](https://docs.rs/digest) | `digest` | Cryptographic hash functions |
//! | [`mac`](https://docs.rs/crypto-mac) | `mac` | Message Authentication Codes (i.e. symmetric message authentication) |
//! | [`signature`](https://docs.rs/signature) | `signature` | Digital signatures (i.e. public key-based message authentication) |
//! | [`stream_cipher`](https://docs.rs/stream-cipher) | `stream-cipher` | Ciphers based on randomly generated keystreams (i.e. low-level symmetric encryption) |
//! | [`universal_hash`](https://docs.rs/universal-hash) | `universal-hash` | Universal Hash Functions (used to build MACs) |
//!
//! [1]: https://github.com/RustCrypto/traits
//! [2]: https://github.com/RustCrypto

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

#[cfg(feature = "aead")]
pub use aead;

#[cfg(feature = "block-cipher")]
pub use block_cipher;

#[cfg(feature = "digest")]
pub use digest;

#[cfg(feature = "mac")]
pub use mac;

#[cfg(feature = "signature")]
pub use signature;

#[cfg(feature = "stream-cipher")]
pub use stream_cipher;

#[cfg(feature = "universal-hash")]
pub use universal_hash;
