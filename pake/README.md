# [RustCrypto]: Password-Authenticated Key Exchange

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Traits which describe the functionality of [Password-Authenticated Key Exchange] (PAKE) algorithms.

## About

Password-Authenticated Key Exchange (PAKE) algorithms can be used to establish a shared secret over an insecure channel
using only the client's knowledge of a password and the server's knowledge of a password hash for authentication. They
can be thought of like other authenticated key exchange algorithms, like the ones in TLS which use X.509 certificates
for identity, but where the identity is entirely established by the user's username and password, all without the client
ever revealing their plaintext password to the server.

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

[crate-image]: https://img.shields.io/crates/v/pake.svg
[crate-link]: https://crates.io/crates/pake
[docs-image]: https://docs.rs/pake/badge.svg
[docs-link]: https://docs.rs/pake/
[build-image]: https://github.com/RustCrypto/traits/actions/workflows/pake.yml/badge.svg
[build-link]: https://github.com/RustCrypto/traits/actions/workflows/pake.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/channel/260043-KDFs

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[Password-Authenticated Key Exchange]: https://en.wikipedia.org/wiki/Password-authenticated_key_agreement#Types
[password hashing functions]: https://en.wikipedia.org/wiki/Key_derivation_function#Password_hashing
