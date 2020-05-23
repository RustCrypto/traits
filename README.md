# RustCrypto: Traits ![Rust Version][rustc-image]

Collection of traits which describe functionality of cryptographic primitives.

## Crates

| Name               | Algorithm                     | Crates.io | Documentation  | Build |
|--------------------|-------------------------------|-----------|----------------|-------|
| [`aead`]           | [Authenticated encryption]    | [![crates.io](https://img.shields.io/crates/v/aead.svg)](https://crates.io/crates/aead) | [![Documentation](https://docs.rs/aead/badge.svg)](https://docs.rs/aead) | ![build](https://github.com/RustCrypto/traits/workflows/aead/badge.svg?branch=master&event=push) |
| [`block-cipher-trait`] | [Block cipher]            | [![crates.io](https://img.shields.io/crates/v/block-cipher-trait.svg)](https://crates.io/crates/block-cipher-trait) | [![Documentation](https://docs.rs/block-cipher-trait/badge.svg)](https://docs.rs/block-cipher-trait) | ![build](https://github.com/RustCrypto/traits/workflows/block-cipher-trait/badge.svg?branch=master&event=push) |
| [`crypto-mac`]     | [Message authentication code] | [![crates.io](https://img.shields.io/crates/v/crypto-mac.svg)](https://crates.io/crates/crypto-mac) | [![Documentation](https://docs.rs/crypto-mac/badge.svg)](https://docs.rs/crypto-mac) | ![build](https://github.com/RustCrypto/traits/workflows/crypto-mac/badge.svg?branch=master&event=push) |
| [`digest`]         | [Cryptographic hash function] | [![crates.io](https://img.shields.io/crates/v/digest.svg)](https://crates.io/crates/digest) | [![Documentation](https://docs.rs/digest/badge.svg)](https://docs.rs/digest) | ![build](https://github.com/RustCrypto/traits/workflows/digest/badge.svg?branch=master&event=push) |
| [`signature`]      | [Digital signature]           | [![crates.io](https://img.shields.io/crates/v/signature.svg)](https://crates.io/crates/signature) | [![Documentation](https://docs.rs/signature/badge.svg)](https://docs.rs/signature) | ![build](https://github.com/RustCrypto/traits/workflows/signature/badge.svg?branch=master&event=push) |
| [`stream-cipher`]  | [Stream cipher]               | [![crates.io](https://img.shields.io/crates/v/stream-cipher.svg)](https://crates.io/crates/stream-cipher) | [![Documentation](https://docs.rs/stream-cipher/badge.svg)](https://docs.rs/stream-cipher) | ![build](https://github.com/RustCrypto/traits/workflows/stream-cipher/badge.svg?branch=master&event=push) |
| [`universal-hash`] | [Universal hash function]     | [![crates.io](https://img.shields.io/crates/v/universal-hash.svg)](https://crates.io/crates/universal-hash) | [![Documentation](https://docs.rs/universal-hash/badge.svg)](https://docs.rs/universal-hash) | ![build](https://github.com/RustCrypto/traits/workflows/universal-hash/badge.svg?branch=master&event=push) |

### Minimum Rust version

All crates in this repository support Rust 1.41 or higher unless otherwise noted.

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

[//]: # (crates)

[`aead`]: https://github.com/RustCrypto/traits/tree/master/aead
[`block-cipher-trait`]: https://github.com/RustCrypto/traits/tree/master/block-cipher-trait
[`crypto-mac`]: https://github.com/RustCrypto/traits/tree/master/crypto-mac
[`digest`]: https://github.com/RustCrypto/traits/tree/master/digest
[`signature`]: https://github.com/RustCrypto/traits/tree/master/signature
[`stream-cipher`]: https://github.com/RustCrypto/traits/tree/master/stream-cipher
[`universal-hash`]: https://github.com/RustCrypto/traits/tree/master/universal-hash

[//]: # (algorithms)

[Authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
[Block cipher]: https://en.wikipedia.org/wiki/Block_cipher
[Message authentication code]: https://en.wikipedia.org/wiki/Message_authentication_code
[Cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
[Digital signature]: https://en.wikipedia.org/wiki/Digital_signature
[Stream cipher]: https://en.wikipedia.org/wiki/Stream_cipher
[Universal hash function]: https://en.wikipedia.org/wiki/Universal_hashing
