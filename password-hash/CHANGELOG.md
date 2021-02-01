# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.1 (2021-02-01)
### Added
- `Encoding` enum with bcrypt and `crypt(3)` Base64 support ([#515])
- Support for using `PasswordHash` with an alternate `Encoding` ([#518])

### Changed
- Bump `base64ct` dependency to v0.2 ([#519])

[#515]: https://github.com/RustCrypto/traits/pull/515
[#518]: https://github.com/RustCrypto/traits/pull/518
[#519]: https://github.com/RustCrypto/traits/pull/519

## 0.1.0 (2021-01-28)
- Initial release
