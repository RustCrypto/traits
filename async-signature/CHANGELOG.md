# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (2024-01-02)
### Added
- Debug impls ([#1407])

### Changed
- Move to AFIT; MSRV 1.75 ([#1428])

### Removed
- `'static` bounds ([#1430])

[#1407]: https://github.com/RustCrypto/traits/pull/1407
[#1428]: https://github.com/RustCrypto/traits/pull/1428
[#1430]: https://github.com/RustCrypto/traits/pull/1430

## 0.4.0 (2023-11-12)
### Changed
- MSRV 1.60 ([#1387])

### Removed
- Mandatory `Send` + `Sync` bounds ([#1375])

[#1375]: https://github.com/RustCrypto/traits/pull/1375
[#1387]: https://github.com/RustCrypto/traits/pull/1387

## 0.3.0 (2023-01-15)
### Changed
- Bump `signature` to v2 ([#1141], [#1211])

### Removed
- `AsyncKeypair` is no longer needed due to `signature` v2 bounds changes ([#1141])

[#1141]: https://github.com/RustCrypto/traits/pull/1141
[#1211]: https://github.com/RustCrypto/traits/pull/1211

## 0.2.1 (2022-09-15)
### Changed
- Relax `AsyncKeypair` bounds ([#1107])
- Deprecate `AsyncKeypair` ([#1112])

[#1107]: https://github.com/RustCrypto/traits/pull/1107
[#1112]: https://github.com/RustCrypto/traits/pull/1112

## 0.2.0 (2022-08-14) [YANKED]
### Added
- `AsyncKeypair` trait ([#1085])

### Changed
- Bump minimum `signature` requirement to v1.6 ([#1084])

[#1084]: https://github.com/RustCrypto/traits/pull/1084
[#1085]: https://github.com/RustCrypto/traits/pull/1085

## 0.1.0 (2022-01-04)
### Changed
- Bump `signature` crate dependency to v1.5 ([#850], [#867])

[#850]: https://github.com/RustCrypto/traits/pull/850
[#867]: https://github.com/RustCrypto/traits/pull/867

## 0.0.1 (2020-10-06)
- Initial release
