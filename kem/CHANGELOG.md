# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2026-02-04)

This release is effectively a complete rewrite of the `kem` crate. Any similarities between trait
names in this release and previous releases is coincidental. The log below highlights some of the
new parts of the API but will provide an incomplete picture of changes.

### Added
- `Encapsulate` and `Decapsulate` traits ([#1509])
- `getrandom` feature ([#2140])
- Re-exports from `crypto-common` ([#2222])
  - re-exports `crypto-common` itself as `common`
  - re-exports `KeyInit`, which is useful for seeds
  - re-exports `Key` as the type for representing serialized encapsulation and decapsulation keys
  - re-exports `InvalidKey` as the error when `TryKeyInit` fails
- `TryDecapsulate` trait ([#2220], [#2235])
- `Kem` trait for the whole algorithm type family ([#2243])
- `FromSeed` trait and `Seed` type alias ([#2284])

### Changed
- `Decapsulator` trait replaced with new implementation ([#2282])

### Removed
- Previous implementation ([#1509])

[#1509]: https://github.com/RustCrypto/traits/pull/1509
[#2140]: https://github.com/RustCrypto/traits/pull/2140
[#2140]: https://github.com/RustCrypto/traits/pull/2140
[#2222]: https://github.com/RustCrypto/traits/pull/2222
[#2220]: https://github.com/RustCrypto/traits/pull/2220
[#2235]: https://github.com/RustCrypto/traits/pull/2235
[#2243]: https://github.com/RustCrypto/traits/pull/2243
[#2284]: https://github.com/RustCrypto/traits/pull/2284

### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#1759])
- Bump `rand_core` to v0.10 ([#2250])

[#1759]: https://github.com/RustCrypto/traits/pull/1759
[#2250]: https://github.com/RustCrypto/traits/pull/2250

## 0.2.0 (2022-05-26)
### Added
- Generic `SharedSecret` type ([#982])
- `EncappedKey::EncappedKeySize` associated constant ([#982])

### Changed
- Rename `EncappedKey::NSecret` => `EncappedKey::SharedSecretSize` ([#982])
- Add `EncappedKey::{from_bytes, as_bytes}` methods ([#982])

[#982]: https://github.com/RustCrypto/traits/pull/982

## 0.1.0 (2022-01-03)
- Initial release
