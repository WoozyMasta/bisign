# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][],
and this project adheres to [Semantic Versioning][].

<!--
## Unreleased

### Added
### Changed
### Removed
-->

## [Unreleased]

### Changed

* Bound memory use while parsing BI keys and signatures
  by validating declared lengths before allocation
  and limiting key-name and RSA-key sizes.
* Cap input sizes at 4 KiB for `.bikey`,
  16 KiB for `.biprivatekey` and `.bisign`,
  and 32 KiB for PEM/DER RSA private keys.
* Lowered the minimum Go version to 1.22.

### Removed

* Removed OpenSSH private-key parsing and its `golang.org/x/crypto` dependency.
  `LoadRSAPrivate` continues to support PEM and DER keys.

[0.2.0]: https://github.com/WoozyMasta/bisign/compare/v0.1.0...v0.2.0

## [0.1.0][] - 2026-02-21

### Added

* First public release

[0.1.0]: https://github.com/WoozyMasta/bisign/tree/v0.1.0

<!--links-->
[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
