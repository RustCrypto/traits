# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0-pre.1 (2019-10-27)
### Changed
- Use `Error::source` instead of `::cause` ([RustCrypto/signatures#37])

### Removed
- Remove `alloc` feature; MSRV 1.34+ ([RustCrypto/signatures#38])

[RustCrypto/signatures#38]: https://github.com/RustCrypto/signatures/pull/38
[RustCrypto/signatures#37]: https://github.com/RustCrypto/signatures/pull/37

## 1.0.0-pre.0 (2019-10-11)
### Changed
- Revert removal of `DigestSignature` ([RustCrypto/signatures#33])
- 1.0 stabilization proposal ([RustCrypto/signatures#32])

[RustCrypto/signatures#33]: https://github.com/RustCrypto/signatures/pull/33
[RustCrypto/signatures#32]: https://github.com/RustCrypto/signatures/pull/32

## 0.3.0 (2019-10-10)
### Changed
- Simplify alloc gating; MSRV 1.36+ ([RustCrypto/signatures#28])
- Replace `DigestSignature` trait with `#[digest(...)]` attribute ([RustCrypto/signatures#27])
- signature_derive: Upgrade to 1.x proc macro crates ([RustCrypto/signatures#26])

[RustCrypto/signatures#28]: https://github.com/RustCrypto/signatures/pull/28
[RustCrypto/signatures#27]: https://github.com/RustCrypto/signatures/pull/27
[RustCrypto/signatures#26]: https://github.com/RustCrypto/signatures/pull/27

## 0.2.0 (2019-06-06)
### Added
- `signature_derive`: Custom derive support for `Signer`/`Verifier` ([RustCrypto/signatures#18])

### Changed
- Have `DigestSigner`/`DigestVerifier` take `Digest` instance ([RustCrypto/signatures#17])

[RustCrypto/signatures#18]: https://github.com/RustCrypto/signatures/pull/18
[RustCrypto/signatures#17]: https://github.com/RustCrypto/signatures/pull/17

## 0.1.0 (2019-05-25)

- Initial release
