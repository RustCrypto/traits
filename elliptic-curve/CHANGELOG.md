# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (2020-08-10)
### Added
- `Arithmetic` trait ([#219])
- `Generate` trait ([#220], [#226])
- Toplevel `Curve` trait ([#223])
- `Invert` trait ([#228])
- `FromPublicKey` trait ([#229], [#248])
- Re-export `zeroize` ([#233])
- OID support ([#240], [#245])
- `NonZeroScalar` type ([#241])
- `Generator` trait ([#241])
- `weierstrass::PublicKey::compress` method ([#243])
- Derive `Clone` on `SecretKey` ([#244])
- Generic Elliptic Curve Diffie-Hellman support ([#251])

### Changed
- Moved repo to https://github.com/RustCrypto/traits ([#213])
- Rename `ScalarBytes` to `ElementBytes` ([#246])
- Rename `CompressedCurvePoint`/`UncompressedCurvePoint` to
  `CompressedPoint`/`UncompressedPoint`

[#213]: https://github.com/RustCrypto/traits/pull/213
[#219]: https://github.com/RustCrypto/traits/pull/219
[#220]: https://github.com/RustCrypto/traits/pull/220
[#223]: https://github.com/RustCrypto/traits/pull/223
[#226]: https://github.com/RustCrypto/traits/pull/226
[#228]: https://github.com/RustCrypto/traits/pull/228
[#229]: https://github.com/RustCrypto/traits/pull/229
[#233]: https://github.com/RustCrypto/traits/pull/233
[#240]: https://github.com/RustCrypto/traits/pull/240
[#241]: https://github.com/RustCrypto/traits/pull/241
[#243]: https://github.com/RustCrypto/traits/pull/243
[#244]: https://github.com/RustCrypto/traits/pull/244
[#245]: https://github.com/RustCrypto/traits/pull/245
[#246]: https://github.com/RustCrypto/traits/pull/246
[#248]: https://github.com/RustCrypto/traits/pull/248
[#251]: https://github.com/RustCrypto/traits/pull/251

## 0.4.0 (2020-06-04)
### Changed
- Bump `generic-array` dependency from v0.12 to v0.14

## 0.3.0 (2020-01-15)
### Added
- `Scalar` struct type

### Changed
- Repository moved to <https://github.com/RustCrypto/elliptic-curves>

### Removed
- Curve definitions/arithmetic extracted out into per-curve crates

## 0.2.0 (2019-12-11)
### Added
- `secp256r1` (P-256) point compression and decompression

### Changed
- Bump MSRV to 1.37

## 0.1.0 (2019-12-06)
- Initial release
