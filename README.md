# RustCrypto: Traits ![Rust Version][rustc-image] [![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link]

Collection of traits which describe functionality of cryptographic primitives.

## Crates

| Crate name          | Algorithm                     | Crates.io | Docs  | Build Status |
|---------------------|-------------------------------|-----------|-------|--------------|
| [`aead`]            | [Authenticated encryption]    | [![crates.io](https://img.shields.io/crates/v/aead.svg)](https://crates.io/crates/aead) | [![Documentation](https://docs.rs/aead/badge.svg)](https://docs.rs/aead) | ![build](https://github.com/RustCrypto/traits/workflows/aead/badge.svg?branch=master&event=push) |
| [`async‑signature`] | [Digital signature]           | [![crates.io](https://img.shields.io/crates/v/async-signature.svg)](https://crates.io/crates/async-signature) | [![Documentation](https://docs.rs/async-signature/badge.svg)](https://docs.rs/async-signature) | ![build](https://github.com/RustCrypto/traits/workflows/async-signature/badge.svg?branch=master&event=push) |
| [`cipher`]          | [Block] and [stream cipher]   | [![crates.io](https://img.shields.io/crates/v/cipher.svg)](https://crates.io/crates/cipher) | [![Documentation](https://docs.rs/cipher/badge.svg)](https://docs.rs/cipher) | ![build](https://github.com/RustCrypto/traits/workflows/cipher/badge.svg?branch=master&event=push) |
| [`crypto‑mac`]      | [Message authentication code] | [![crates.io](https://img.shields.io/crates/v/crypto-mac.svg)](https://crates.io/crates/crypto-mac) | [![Documentation](https://docs.rs/crypto-mac/badge.svg)](https://docs.rs/crypto-mac) | ![build](https://github.com/RustCrypto/traits/workflows/crypto-mac/badge.svg?branch=master&event=push) |
| [`digest`]          | [Cryptographic hash function] | [![crates.io](https://img.shields.io/crates/v/digest.svg)](https://crates.io/crates/digest) | [![Documentation](https://docs.rs/digest/badge.svg)](https://docs.rs/digest) | ![build](https://github.com/RustCrypto/traits/workflows/digest/badge.svg?branch=master&event=push) |
| [`elliptic‑curve`]  | [Elliptic curve cryptography] | [![crates.io](https://img.shields.io/crates/v/elliptic-curve.svg)](https://crates.io/crates/elliptic-curve) | [![Documentation](https://docs.rs/elliptic-curve/badge.svg)](https://docs.rs/elliptic-curve) | ![build](https://github.com/RustCrypto/traits/workflows/elliptic-curve/badge.svg?branch=master&event=push) |
| [`password-hash`]   | [Password hashing]            | [![crates.io](https://img.shields.io/crates/v/password-hash.svg)](https://crates.io/crates/password-hash) | [![Documentation](https://docs.rs/password-hash/badge.svg)](https://docs.rs/password-hash) | ![build](https://github.com/RustCrypto/traits/workflows/password-hash/badge.svg?branch=master&event=push) |
| [`signature`]       | [Digital signature]           | [![crates.io](https://img.shields.io/crates/v/signature.svg)](https://crates.io/crates/signature) | [![Documentation](https://docs.rs/signature/badge.svg)](https://docs.rs/signature) | ![build](https://github.com/RustCrypto/traits/workflows/signature/badge.svg?branch=master&event=push) |
| [`universal‑hash`]  | [Universal hash function]     | [![crates.io](https://img.shields.io/crates/v/universal-hash.svg)](https://crates.io/crates/universal-hash) | [![Documentation](https://docs.rs/universal-hash/badge.svg)](https://docs.rs/universal-hash) | ![build](https://github.com/RustCrypto/traits/workflows/universal-hash/badge.svg?branch=master&event=push) |

### Additional crates

| Crate name | Description             | Crates.io | Docs  | Build Status |
|------------|-------------------------|-----------|-------|--------------|
| [`crypto`] | Facade for trait crates | [![crates.io](https://img.shields.io/crates/v/crypto.svg)](https://crates.io/crates/crypto) | [![Documentation](https://docs.rs/crypto/badge.svg)](https://docs.rs/crypto) | ![build](https://github.com/RustCrypto/traits/workflows/crypto/badge.svg?branch=master&event=push)

### Minimum Supported Rust Version

All crates in this repository support **Rust 1.41** or higher unless otherwise noted.

In future minimally supported version of Rust can be changed, but it will be done
with the minor version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/
[deps-image]: https://deps.rs/repo/github/RustCrypto/traits/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/traits

[//]: # (crates)

[`aead`]: https://github.com/RustCrypto/traits/tree/master/aead
[`async‑signature`]: https://github.com/RustCrypto/traits/tree/master/signature/async
[`cipher`]: https://github.com/RustCrypto/traits/tree/master/cipher
[`crypto‑mac`]: https://github.com/RustCrypto/traits/tree/master/crypto-mac
[`crypto`]: https://github.com/RustCrypto/traits/tree/master/crypto
[`digest`]: https://github.com/RustCrypto/traits/tree/master/digest
[`elliptic‑curve`]: https://github.com/RustCrypto/traits/tree/master/elliptic-curve
[`password-hash`]: https://github.com/RustCrypto/traits/tree/master/password-hash
[`signature`]: https://github.com/RustCrypto/traits/tree/master/signature
[`universal‑hash`]: https://github.com/RustCrypto/traits/tree/master/universal-hash

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
