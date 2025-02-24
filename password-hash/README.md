# RustCrypto: Password Hashing Traits

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Traits which describe the functionality of [password hashing algorithms].

## About

Provides a `no_std`-friendly implementation of the
[Password Hashing Competition (PHC) string format specification][PHC]
(a well-defined subset of the [Modular Crypt Format a.k.a. MCF][MCF]) which
works in conjunction with the traits this crate defines.

## Supported Crates

See [RustCrypto/password-hashes] for algorithm implementations which use
this crate for interoperability:

- [`argon2`] - Argon2 memory hard key derivation function
- [`pbkdf2`] - Password-Based Key Derivation Function v2
- [`scrypt`] - scrypt key derivation function

## License

Licensed under either of:

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/password-hash
[crate-link]: https://crates.io/crates/password-hash
[docs-image]: https://docs.rs/password-hash/badge.svg
[docs-link]: https://docs.rs/password-hash/
[build-image]: https://github.com/RustCrypto/traits/actions/workflows/password-hash.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/traits/actions/workflows/password-hash.yml?query=branch:master
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes

[//]: # (general links)

[password hashing algorithms]: https://en.wikipedia.org/wiki/Cryptographic_hash_function#Password_verification
[PHC]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
[MCF]: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
[RustCrypto/password-hashes]: https://github.com/RustCrypto/password-hashes
[`argon2`]: https://docs.rs/argon2
[`pbkdf2`]: https://docs.rs/pbkdf2
[`scrypt`]: https://docs.rs/scrypt
