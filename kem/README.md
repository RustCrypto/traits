# [RustCrypto]: Key Encapsulation Mechanisms (KEMs)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

## About

This crate provides a common set of traits for [key encapsulation mechanisms][1]—algorithms for
non-interactively establishing secrets between peers.

This is intended to be implemented by libraries which produce or contain implementations of key
encapsulation mechanisms, and used by libraries which want to produce or consume encapsulated
secrets while generically supporting any compatible backend.

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
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures
[build-image]: https://github.com/RustCrypto/traits/actions/workflows/kem.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/traits/actions/workflows/kem.yml?query=branch:master

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[1]: https://en.wikipedia.org/wiki/Key_encapsulation
