# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (UNRELEASED)
### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#1759])

[#1759]: https://github.com/RustCrypto/traits/pull/1759

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
