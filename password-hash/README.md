# RustCrypto: Password Hashing Traits

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Traits which describe the functionality of [password hashing algorithms].

## About

This crate contains traits for using password hashing algorithms to create and verify password hash strings of the sort
used by the [`crypt(3)`] API, which typically begin with `${ident}$...`.

It provides first-class support for the
[Password Hashing Competition (PHC) string format specification][PHC]
via the [`phc` crate] and can also be used with the
[Modular Crypt Format (MCF)][MCF])
via the [`mcf` crate].

## Supported Password Hashing Algorithms

See [RustCrypto/password-hashes] for algorithm implementations which use
this crate for interoperability:

- [`argon2`]: Argon2 memory hard key derivation function
- [`balloon-hash`]: PBKDF with proven memory-hard password-hashing and modern design
- [`pbkdf2`]: Password-Based Key Derivation Function V2
- [`scrypt`]: scrypt key derivation function
- [`sha-crypt`]: SHA-crypt legacy password hashing algorithm for `crypt(3)`
- [`yescrypt`]: yescrypt key derivation (improved version of scrypt)

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
[`crypt(3)`]: https://en.wikipedia.org/wiki/Crypt_(C)
[PHC]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
[`phc` crate]: https://docs.rs/phc
[MCF]: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
[`mcf` crate]: https://docs.rs/mcf
[RustCrypto/password-hashes]: https://github.com/RustCrypto/password-hashes
[`argon2`]: https://docs.rs/argon2
[`balloon-hash`]: https://docs.rs/balloon-hash
[`pbkdf2`]: https://docs.rs/pbkdf2
[`scrypt`]: https://docs.rs/scrypt
[`sha-crypt`]: https://docs.rs/sha-crypt
[`yescrypt`]: https://docs.rs/yescrypt
