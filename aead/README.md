# RustCrypto: Authenticated Encryption with Additional Data Traits

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

This crate provides an abstract interface for [AEAD] ciphers, which guarantee
both confidentiality and integrity, even from a powerful attacker who is
able to execute [chosen-ciphertext attacks]. The resulting security property,
[ciphertext indistinguishability], is considered a basic requirement for
modern cryptographic implementations.

See [RustCrypto/AEADs] for cipher implementations which implement traits from
this crate.

## Nonces: ⚠️ Security Warning ⚠️

AEAD algorithms accept a parameter to encryption/decryption called
a "nonce" which must be unique every time encryption is performed and
never repeated for the same key. The nonce is often prepended to the
ciphertext. The nonce used to produce a given ciphertext must be passed
to the decryption function in order for it to decrypt correctly.

AEAD algorithms often fail catastrophically if nonces are ever repeated
for the same key (with SIV modes being a "misuse-resistent" exception).

Nonces don't necessarily have to be random, but it is one strategy
which is often used in practice.

Using random nonces runs the risk of repeating them unless the nonce
size is particularly large, e.g. 192-bit extended nonces used by the
`XChaCha20Poly1305` and `XSalsa20Poly1305` constructions.

[NIST SP 800-38D] recommends the following for 128-bit nonces:

> The total number of invocations of the authenticated encryption
> function shall not exceed 2^32, including all IV lengths and all
> instances of the authenticated encryption function with the given key.

Following this guideline, only 4,294,967,296 messages with random
nonces can be encrypted under a given key. While this bound is high,
it's possible to encounter in practice, and systems which might
reach it should consider alternatives to purely random nonces, like
a counter or a combination of a random nonce + counter.

See the [`aead-stream`] crate for a ready-made implementation of the latter.

[NIST SP 800-38D]: https://csrc.nist.gov/publications/detail/sp/800-38d/final
[`aead-stream`]: https://docs.rs/aead-stream

## Minimum Supported Rust Version

Rust **1.81** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

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

[crate-image]: https://img.shields.io/crates/v/aead.svg
[crate-link]: https://crates.io/crates/aead
[docs-image]: https://docs.rs/aead/badge.svg
[docs-link]: https://docs.rs/aead/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/traits/workflows/aead/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/traits/actions?query=workflow%3Aaead

[//]: # (general links)

[AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption
[chosen-ciphertext attacks]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
[ciphertext indistinguishability]: https://en.wikipedia.org/wiki/Ciphertext_indistinguishability
[RustCrypto/AEADs]: https://github.com/RustCrypto/AEADs
