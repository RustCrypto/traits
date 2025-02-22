# RustCrypto: `crypto` crate

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Facade crate for [RustCrypto Traits][1], providing a single place to
access compatible versions of all traits from the Rust Crypto project.

[Documentation][docs-link]

## About

Facade crate for [RustCrypto Traits][1], providing a single place to
access compatible versions of all traits from the Rust Crypto project.

# About

The [RustCrypto Project][2] publishes and maintains independently versioned
crates containing traits for many different kinds of cryptographic
algorithms.

However, these algorithms are often interdependent (e.g. many depend on digest
algorithms), which requires figuring out which versions of the trait crates
are compatible with each other.

This crate will automatically pull in compatible versions of these crates,
with each one gated under a cargo feature, providing a single place to both
import and upgrade these crates while ensuring they remain compatible.

# Traits

The following traits are available as re-exports of RustCrypto crates through
this crate's facade. To access a particular re-export you (or a crate you
depend on) must enable the associated Cargo feature named below.

| Re-export | Cargo feature | Description |
|-----------|---------------|-------------|
| [`aead`](https://docs.rs/aead) | `aead` | Authenticated Encryption with Associated Data (i.e. high-level symmetric encryption) |
| [`cipher`](https://docs.rs/cipher) | `cipher` | Block and stream ciphers (i.e. low-level symmetric encryption) |
| [`digest`](https://docs.rs/digest) | `digest` | Cryptographic hash functions |
| [`elliptic_curve`](https://docs.rs/elliptic-curve) | `elliptic-curve` | Elliptic curve cryptography |
| [`password_hash`](https://docs.rs/password-hash) | `password-hash` | Password hashing functions |
| [`signature`](https://docs.rs/signature) | `signature` | Digital signatures (i.e. public key-based message authentication) |
| [`universal_hash`](https://docs.rs/universal-hash) | `universal‑hash` | Universal Hash Functions (used to build MACs) |

[1]: https://github.com/RustCrypto/traits
[2]: https://github.com/RustCrypto

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/crypto.svg
[crate-link]: https://crates.io/crates/crypto
[docs-image]: https://docs.rs/crypto/badge.svg
[docs-link]: https://docs.rs/crypto/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260050-Traits
[build-image]: https://github.com/RustCrypto/traits/workflows/crypto/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/traits/actions?query=workflow:crypto

[//]: # (footnotes)

[1]: https://github.com/RustCrypto/traits
