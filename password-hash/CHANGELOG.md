# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.1 (2021-05-05)
### Changed
- Use `subtle` crate for comparing hash `Output` ([#631])

[#631]: https://github.com/RustCrypto/traits/pull/631

## 0.2.0 (2021-04-29)
### Changed
- Allow specifying output length and version with params ([#615])
- Allow passing `&str`, `&Salt`, or `&SaltString` as salt ([#615])
- Simplify error handling ([#615])

[#615]: https://github.com/RustCrypto/traits/pull/615

## 0.1.4 (2021-04-19)
### Added
- Length constants ([#600])

### Changed
- Deprecate functions for obtaining length constants ([#600])

[#600]: https://github.com/RustCrypto/traits/pull/600

## 0.1.3 (2021-04-17)
### Changed
- Update docs for PHC string <version> field ([#593])

### Fixed
- Broken `b64` links in rustdoc ([#594])

[#593]: https://github.com/RustCrypto/traits/pull/593
[#594]: https://github.com/RustCrypto/traits/pull/594

## 0.1.2 (2021-03-17)
### Changed
- Bump `base64ct` dependency to v1.0 ([#579])

[#579]: https://github.com/RustCrypto/traits/pull/579

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
