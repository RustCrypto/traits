# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.6 (2020-10-08)
### Added
- Derive `Clone` on `SecretBytes` ([#330])

[#300]: https://github.com/RustCrypto/traits/pull/300

## 0.6.5 (2020-10-08)
### Fixed
- Work around `nightly-2020-10-06` breakage ([#328])

[#328]: https://github.com/RustCrypto/traits/pull/328

## 0.6.4 (2020-10-08)
### Added
- Impl `From<SecretBytes<C>>` for `FieldBytes<C>` ([#326])

[#326]: https://github.com/RustCrypto/traits/pull/326

## 0.6.3 (2020-10-08)
### Added
- `SecretBytes` newtype ([#324])

[#324]: https://github.com/RustCrypto/traits/pull/324

## 0.6.2 (2020-09-24)
### Added
- `sec1::EncodedPoint::to_untagged_bytes()` method ([#312])

[#312]: https://github.com/RustCrypto/traits/pull/312

## 0.6.1 (2020-09-21)
### Fixed
- `sec1::EncodedPoint::decompress` ([#309])

[#309]: https://github.com/RustCrypto/traits/pull/309

## 0.6.0 (2020-09-11) [YANKED]
### Added
- `arithmetic` feature ([#293])
- Generic curve/field arithmetic using the `ff` and `group` crates
  ([#287], [#291], [#292])
- `sec1::Coordinates` ([#286])
- `weierstrass::point::Compression` trait ([#283], [#300])
- Arithmetic helper functions ([#281])
- `digest` feature and `FromDigest` trait ([#279])
- impl `Deref` for `NonZeroScalar` ([#278])
- Conditionally impl `Invert` for `NonZeroScalar` ([#277])
- `NonZeroScalar::to_bytes` ([#276])
- `EncodedPoint::decompress` ([#275])
- `sec1::Tag` ([#270])
- `weierstrass::point::Decompress` trait ([#266])
- `alloc` feature + `EncodedPoint::to_bytes()` ([#265])

### Changed
- Renamed `Arithmetic` trait to `point::ProjectiveArithmetic` ([#300])
- Replaced `Arithmetic::Scalar` and `Arithmetic::AffinePoint`
  with `Scalar<C>` and `AffinePoint<C>` ([#300])
- Made `SecretKey<C>` inner type generic ([#297])
- Renamed `ElementBytes<C>` to `FieldBytes<C>` ([#296])
- MSRV 1.44 ([#292])
- Minimum `subtle` version now v2.3 ([#290])
- Renamed `Curve::ElementSize` to `::FieldSize` ([#282])
- Refactor `PublicKey` into `sec1::EncodedPoint` ([#264])

### Removed
- `FromBytes` trait ([#300])
- `Generate` trait ([#295])

[#300]: https://github.com/RustCrypto/traits/pull/300
[#297]: https://github.com/RustCrypto/traits/pull/297
[#296]: https://github.com/RustCrypto/traits/pull/296
[#295]: https://github.com/RustCrypto/traits/pull/295
[#293]: https://github.com/RustCrypto/traits/pull/293
[#292]: https://github.com/RustCrypto/traits/pull/292
[#291]: https://github.com/RustCrypto/traits/pull/291
[#290]: https://github.com/RustCrypto/traits/pull/290
[#287]: https://github.com/RustCrypto/traits/pull/293
[#286]: https://github.com/RustCrypto/traits/pull/286
[#283]: https://github.com/RustCrypto/traits/pull/283
[#282]: https://github.com/RustCrypto/traits/pull/282
[#281]: https://github.com/RustCrypto/traits/pull/281
[#279]: https://github.com/RustCrypto/traits/pull/279
[#278]: https://github.com/RustCrypto/traits/pull/278
[#277]: https://github.com/RustCrypto/traits/pull/277
[#276]: https://github.com/RustCrypto/traits/pull/276
[#275]: https://github.com/RustCrypto/traits/pull/275
[#270]: https://github.com/RustCrypto/traits/pull/270
[#266]: https://github.com/RustCrypto/traits/pull/266
[#265]: https://github.com/RustCrypto/traits/pull/265
[#264]: https://github.com/RustCrypto/traits/pull/264

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
