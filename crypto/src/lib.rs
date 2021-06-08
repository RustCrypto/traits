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
//! The following traits are available as re-exports of RustCrypto crates through
//! this crate's facade. To access a particular re-export you (or a crate you
//! depend on) must enable the associated Cargo feature named below.
//!
//! | Re-export | Cargo feature | Description |
//! |-----------|---------------|-------------|
//! | [`aead`](https://docs.rs/aead) | `aead` | Authenticated Encryption with Associated Data (i.e. high-level symmetric encryption) |
//! | [`cipher`](https://docs.rs/cipher) | `cipher` | Block and stream ciphers (i.e. low-level symmetric encryption) |
//! | [`digest`](https://docs.rs/digest) | `digest` | Cryptographic hash functions |
//! | [`elliptic_curve`](https://docs.rs/elliptic-curve) | `elliptic-curve` | Elliptic curve cryptography |
//! | [`mac`](https://docs.rs/crypto-mac) | `mac` | Message Authentication Codes (i.e. symmetric message authentication) |
//! | [`password_hash`](https://docs.rs/password-hash) | `password-hash` | Password hashing functions |
//! | [`signature`](https://docs.rs/signature) | `signature` | Digital signatures (i.e. public key-based message authentication) |
//! | [`universal_hash`](https://docs.rs/universal-hash) | `universal‑hash` | Universal Hash Functions (used to build MACs) |
//!
//! [1]: https://github.com/RustCrypto/traits
//! [2]: https://github.com/RustCrypto

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/crypto/0.3.0"
)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

#[cfg(feature = "aead")]
pub use aead;

#[cfg(feature = "cipher")]
pub use cipher;

#[cfg(feature = "digest")]
pub use digest;

#[cfg(feature = "elliptic-curve")]
pub use elliptic_curve;

#[cfg(feature = "mac")]
pub use mac;

#[cfg(feature = "password-hash")]
pub use password_hash;

#[cfg(feature = "signature")]
pub use signature;

#[cfg(feature = "universal-hash")]
pub use universal_hash;
