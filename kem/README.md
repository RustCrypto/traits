# [RustCrypto]: Key Encapsulation Mechanisms (KEMs)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

This crate provides a common set of traits for [key encapsulation mechanisms][1]—algorithms for non-interactively establishing secrets between peers. This is intended to be implemented by libraries which produce or contain implementations of key encapsulation mechanisms, and used by libraries which want to produce or consume encapsulated secrets while generically supporting any compatible backend.

The crate exposes four traits, `Encapsulator`, `Decapsulator`, `AuthEncapsulator`, and `AuthDecapsulator`. These traits represent the ability to initiate a key exchange and complete a key exchange, in the case where the sender is authenticated to the receiver and in the case where the sender is not.

[Documentation][docs-link]

## Minimum Supported Rust Version

Rust **1.56** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/kem.svg
[crate-link]: https://crates.io/crates/kem
[docs-image]: https://docs.rs/kem/badge.svg
[docs-link]: https://docs.rs/kem/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures
[build-image]: https://github.com/RustCrypto/traits/workflows/kem/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/traits/actions?query=workflow%3Akem

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[1]: https://en.wikipedia.org/wiki/Key_encapsulation
