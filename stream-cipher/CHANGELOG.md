# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.8.0-pre (2020-10-14)
### Added
- `FromBlockCipherMut` trait ([#334])

### Removed
- `NewBlockCipher` bound on `FromBlockCipher` ([#333])

[#334]: https://github.com/RustCrypto/traits/pull/334
[#333]: https://github.com/RustCrypto/traits/pull/333

## 0.7.1 (2020-08-25)
### Fixed
- Computation of `SeekNum::to_block_byte` for numbers which are not a power of 2 ([#268])

[#268]: https://github.com/RustCrypto/traits/pull/268

## 0.7.0 (2020-08-25)
### Changed
- Rework of the `SyncStreamCipherSeek` trait, make methods generic over
numeric types, add fallable `try_seek` and `try_current_pos` methods ([#260])
- Rework macro for generating seek tests, re-export `blobby` at top-level,
remove the `dev` module from public API ([#260])

[#260]: https://github.com/RustCrypto/traits/pull/260

## 0.6.0 (2020-07-10)
### Changed
- Add blanket implementation for `&mut SyncCtreamCipher` ([#210])
- Update to `blobby v0.3` ([#210])

[#210]: https://github.com/RustCrypto/traits/pull/210

## 0.5.0 (2020-07-03)
### Changed
- Add `NonceSize` associated type to the `FromBlockCipher` trait ([#209])

[#209]: https://github.com/RustCrypto/traits/pull/209

## 0.4.1 (2020-06-10)
### Added
- `Key` and `Nonce` type aliases ([#188])

[#188]: https://github.com/RustCrypto/traits/issues/188

## 0.4.0 (2020-06-04)
### Added
- `FromBlockCipher` trait ([#164])

### Changed
- Update to 2018 edition ([#110])
- Bump `generic-array` dependency to v0.14 ([#95])

[#164]: https://github.com/RustCrypto/traits/issues/164
[#110]: https://github.com/RustCrypto/traits/issues/110
[#95]: https://github.com/RustCrypto/traits/pull/95

## 0.3.2 (2019-08-18)

## 0.3.1 (2019-08-17)

## 0.3.0 (2018-11-01)

## 0.2.2 (2018-10-16)

## 0.2.1 (2018-10-04)

## 0.2.0 (2018-10-03)

## 0.1.1 (2018-08-08)

## 0.1.0 (2018-07-27)
