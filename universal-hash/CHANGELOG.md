# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 (2020-06-04)
### Added
- `Key` and `Block` type aliases ([#128])

### Changed
- Split `UniversalHash` initialization into `NewUniversalHash` trait ([#135])
- Rename `update_block` => `update` ([#129])
- Bump `generic-array` dependency to v0.14 ([#95])

[#135]: https://github.com/RustCrypto/traits/pull/135
[#129]: https://github.com/RustCrypto/traits/pull/129
[#128]: https://github.com/RustCrypto/traits/pull/128
[#95]: https://github.com/RustCrypto/traits/pull/95

## 0.3.0 (2019-10-03)
- Rename `OutputSize` -> `BlockSize` ([#57])

[#57]: https://github.com/RustCrypto/traits/pull/57

## 0.2.0 (2019-08-31)
### Changed
- Split KeySize/OutputSize ([#55])

[#55]: https://github.com/RustCrypto/traits/pull/55

## 0.1.0 (2019-08-30)
- Initial release
