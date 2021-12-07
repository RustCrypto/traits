# RustCrypto: Traits

[![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link] ![Apache2/MIT licensed][license-image]

Collection of traits which describe functionality of cryptographic primitives.

## Crates

| Name                | Algorithm | Crates.io | Docs  | MSRV |
|---------------------|-----------|:---------:|:-----:|:----:|
| [`aead`]            | [Authenticated encryption]    | [![crates.io](https://img.shields.io/crates/v/aead.svg)](https://crates.io/crates/aead) | [![Documentation](https://docs.rs/aead/badge.svg)](https://docs.rs/aead) | ![MSRV 1.41][msrv-1.41] |
| [`async‑signature`] | [Digital signature]           | [![crates.io](https://img.shields.io/crates/v/async-signature.svg)](https://crates.io/crates/async-signature) | [![Documentation](https://docs.rs/async-signature/badge.svg)](https://docs.rs/async-signature) | ![MSRV 1.41][msrv-1.41] |
| [`cipher`]          | [Block] and [stream cipher]   | [![crates.io](https://img.shields.io/crates/v/cipher.svg)](https://crates.io/crates/cipher) | [![Documentation](https://docs.rs/cipher/badge.svg)](https://docs.rs/cipher) | ![MSRV 1.41][msrv-1.41] |
| [`crypto‑common`]      | Common cryptographic traits | [![crates.io](https://img.shields.io/crates/v/crypto-common.svg)](https://crates.io/crates/crypto-common) | [![Documentation](https://docs.rs/crypto-common/badge.svg)](https://docs.rs/crypto-common) | ![MSRV 1.41][msrv-1.41] |
| [`digest`]          | [Cryptographic hash function] | [![crates.io](https://img.shields.io/crates/v/digest.svg)](https://crates.io/crates/digest) | [![Documentation](https://docs.rs/digest/badge.svg)](https://docs.rs/digest) | ![MSRV 1.41][msrv-1.41] |
| [`elliptic‑curve`]  | [Elliptic curve cryptography] | [![crates.io](https://img.shields.io/crates/v/elliptic-curve.svg)](https://crates.io/crates/elliptic-curve) | [![Documentation](https://docs.rs/elliptic-curve/badge.svg)](https://docs.rs/elliptic-curve) | ![MSRV 1.56][msrv-1.56] |
| [`password-hash`]   | [Password hashing]            | [![crates.io](https://img.shields.io/crates/v/password-hash.svg)](https://crates.io/crates/password-hash) | [![Documentation](https://docs.rs/password-hash/badge.svg)](https://docs.rs/password-hash) | ![MSRV 1.47][msrv-1.47] |
| [`signature`]       | [Digital signature]           | [![crates.io](https://img.shields.io/crates/v/signature.svg)](https://crates.io/crates/signature) | [![Documentation](https://docs.rs/signature/badge.svg)](https://docs.rs/signature) | ![MSRV 1.41][msrv-1.41] |
| [`universal‑hash`]  | [Universal hash function]     | [![crates.io](https://img.shields.io/crates/v/universal-hash.svg)](https://crates.io/crates/universal-hash) | [![Documentation](https://docs.rs/universal-hash/badge.svg)](https://docs.rs/universal-hash) | ![MSRV 1.41][msrv-1.41] |

### Additional Crates

| Crate name | Description             | Crates.io | Docs  | MSRV |
|------------|-------------------------|:---------:|:-----:|:----:|
| [`crypto`] | Facade for trait crates | [![crates.io](https://img.shields.io/crates/v/crypto.svg)](https://crates.io/crates/crypto) | [![Documentation](https://docs.rs/crypto/badge.svg)](https://docs.rs/crypto) | ![MSRV 1.56][msrv-1.56] |

### Minimum Supported Rust Version (MSRV) Policy

MSRV bumps are considered breaking changes and will be performed only with minor version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[deps-image]: https://deps.rs/repo/github/RustCrypto/traits/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/traits
[msrv-1.41]: https://img.shields.io/badge/rustc-1.41.0+-blue.svg
[msrv-1.47]: https://img.shields.io/badge/rustc-1.47.0+-blue.svg
[msrv-1.56]: https://img.shields.io/badge/rustc-1.56.0+-blue.svg

[//]: # (crates)

[`aead`]: ./aead
[`async‑signature`]: ./signature/async
[`cipher`]: ./cipher
[`crypto‑common`]: ./crypto-common
[`crypto`]: ./crypto
[`digest`]: ./digest
[`elliptic‑curve`]: ./elliptic-curve
[`password-hash`]: ./password-hash
[`signature`]: ./signature
[`universal‑hash`]: ./universal-hash

[//]: # (algorithms)

[Authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
[Block]: https://en.wikipedia.org/wiki/Block_cipher
[Message authentication code]: https://en.wikipedia.org/wiki/Message_authentication_code
[Cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
[Digital signature]: https://en.wikipedia.org/wiki/Digital_signature
[Elliptic curve cryptography]: https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
[Password hashing]: https://en.wikipedia.org/wiki/Cryptographic_hash_function#Password_verification
[Stream cipher]: https://en.wikipedia.org/wiki/Stream_cipher
[Universal hash function]: https://en.wikipedia.org/wiki/Universal_hashing
