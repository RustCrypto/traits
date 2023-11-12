# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2.1.0 (2023-11-12)
### Changed
- MSRV 1.60 ([#1387])

[#1387]: https://github.com/RustCrypto/traits/pull/1387

## 2.0.1 (2023-04-17)
### Changed
- Bump `syn` to v2 ([#1299])

[#1299]: https://github.com/RustCrypto/traits/pull/1299

## 2.0.0 (2023-01-15)
### Changed
- `Signature` trait has been removed, so don't emit it in custom derive ([#1141])

[#1141]: https://github.com/RustCrypto/traits/pull/1141

## 1.0.0-pre.7 (2022-09-16)
### Fixed
- Support for `where` bounds ([#1118])

[#1118]: https://github.com/RustCrypto/traits/pull/1118

## 1.0.0-pre.6 (2022-09-12)
### Added
- `DigestSigner`/`DigestVerifier` support ([#1103])

### Removed
- `synstructure` dependency ([#1100])

[#1100]: https://github.com/RustCrypto/traits/pull/1100
[#1103]: https://github.com/RustCrypto/traits/pull/1103

## 1.0.0-pre.5 (2022-08-14)
### Changed
- Rust 2021 edition upgrade; MSRV 1.56 ([#1081])

[#1081]: https://github.com/RustCrypto/traits/pull/1081

## 1.0.0-pre.4 (2022-01-04)
### Changed
- Support for new `digest` v0.10 API ([#850])

[#850]: https://github.com/RustCrypto/traits/pull/850

## 1.0.0-pre.3 (2021-01-06)
### Fixed
- rustdoc links ([#458])

[#458]: https://github.com/RustCrypto/traits/pull/458

## 1.0.0-pre.2 (2020-04-19)
### Changed
- Rename `DigestSignature` => `PrehashSignature` ([#96])

[#96]: https://github.com/RustCrypto/traits/pull/96

## 1.0.0-pre.1 (2020-03-08)
### Added
- Initial changelog for `signature_derive`
- rustdoc ([#79])

[#79]: https://github.com/RustCrypto/traits/pull/79
