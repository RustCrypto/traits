# [RustCrypto]: Key Derivation Functions (KDFs)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Traits which describe the functionality of [key derivation functions].

## About

Key Derivation Functions (KDFs) are cryptographic algorithms that can be used to derive one or more secret keys from
a secret value such as a base derivation key, output of a key-exchange algorithm, or in the case of specially designed
password-based key derivation functions: a password.

KDFs can be used to stretch shorter input keys into longer keys or to obtain multiple keys from a single input. They can
also be used to transform non-uniform secret values, like the output of a Diffie-Hellman exchange, into uniformly random
secrets suitable for use as keys for symmetric cryptographic algorithms (e.g. AES, ChaCha20).

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

[crate-image]: https://img.shields.io/crates/v/kdf.svg
[crate-link]: https://crates.io/crates/kdf
[docs-image]: https://docs.rs/kdf/badge.svg
[docs-link]: https://docs.rs/kdf/
[build-image]: https://github.com/RustCrypto/traits/actions/workflows/kdf.yml/badge.svg
[build-link]: https://github.com/RustCrypto/traits/actions/workflows/kdf.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/channel/260043-KDFs

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[key derivation functions]: https://en.wikipedia.org/wiki/Key_derivation_function
