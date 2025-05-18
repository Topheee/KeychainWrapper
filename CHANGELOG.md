# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.1] - 2025-05-18

### Fixed

- Fix reading of asymmetric keys generated prior to major version 2.

## [3.0.0] - 2025-04-26

### Added

- `AsymmetricKeyBacking.properties` property.
- `AsymmetricPublicKey.copyPublicKey()` function.
- Public read-only `KeyPair.tag` property.
- Several tests.

### Changed

- [__breaking__] [API] Renamed `persisted` property to `available`.
- [__breaking__] [API] `KeyPair` behaviour: Only store the private key in the
Keychain and obtain the public key from it. Note that you can still use old
private keys. You should just delete the old public key that is separately
stored in the keychain.
- [__breaking__] [API] Split up `KeyPair.blockSize` (which was the block size
of the private key) into `privateKeyBlockSize` and `publicKeyBlockSize`.
- [__breaking__] [API] Removed the `persistent` parameter, which did not work
anyway.
- [__breaking__] [behaviour] Do not always remove already existing generic
passwords before saving a new one (over) them.
- Moved from XCTest to Swift Testing.

### Fixed

- Rapidly removing a password from the keychain after adding it could run into
errors.

## [2.0.1] - 2025-01-21

### Fixed

- Fix initizialization of public structs.


## [2.0.0] - 2025-01-22

### Changed

- [__breaking__] `KeyPair` is now only a reference to a Keychain item, not a
wrapper around `SecKey` anymore. This allows for `Sendable` conformance.
