# Changelog

All notable changes to StreamHash will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.2] - 2025-01-25

### Added
- Custom high-performance Whirlpool implementation with T-table optimization (#15)
- AES-NI SIMD optimization for Grøstl SubBytes operation (#13)
- SSSE3 SIMD optimization for JH linear transform (#14)
- Bit-sliced S-box implementation for JH

### Changed
- Whirlpool now uses custom T-table implementation instead of BouncyCastle wrapper
- Grøstl MixBytes optimized with T-table lookup
- All SIMD optimizations include scalar fallbacks for compatibility

### Performance
- **Whirlpool**: 3.2x faster (52.4ms → 16.5ms for 1MB)
- **Grøstl**: ~2.5x faster (153ms → 61ms for 1MB) with AES-NI
- **JH**: ~1.4x faster (191ms → 137ms for 1MB) with SSSE3

## [1.6.1] - 2025-01-24

### Changed
- Major memory optimization for JH algorithm (99.99% reduction: 6.6MB → 512B per hash)
- Major memory optimization for Grøstl algorithm (99.91% reduction: 817KB → 752B per hash)
- Pre-allocated buffers eliminate per-block allocations in hot paths

### Fixed
- Algorithm correctness validation across all 71 algorithms (#12)
- Bug fixes for edge cases in cryptographic algorithm implementations

## [1.6.0] - 2025-01-23

### Added
- CRC-16 variants (CCITT, MODBUS, USB)
- FNV-1a hash (32-bit and 64-bit)
- DJB2 and DJB2a string hash algorithms
- SDBM hash algorithm
- Lose Lose hash algorithm
- Total algorithms now at 71

### Changed
- Real Grøstl implementation (previously placeholder)
- Real JH implementation (previously placeholder)
- Comprehensive documentation for all algorithms

## [1.5.0] - 2025-01-22

### Added
- Full BouncyCastle integration for all cryptographic algorithms
- HashFacade unified API for accessing all 71 algorithms
- IStreamingHashBytes interface for byte[] results
- Algorithm metadata (display name, digest size, cryptographic flag)

### Changed
- All 62+ hash algorithms now fully accessible through HashFacade
- Improved test coverage (619+ tests)

## [1.4.0] - 2025-01-21

### Added
- wyhash64 streaming implementation
- xxHash wrappers (xxHash32, xxHash64, xxHash3, xxHash128)

## [1.3.0] - 2025-01-20

### Added
- HashFacade unified API
- HashAlgorithm enum for all algorithms
- Streaming adapters for System.IO.Hashing types

## [1.2.0] - 2025-01-19

### Added
- MetroHash64 and MetroHash128 streaming implementations
- KangarooTwelve (K12) streaming implementation

## [1.1.0] - 2025-01-18

### Added
- CityHash64 and CityHash128 streaming implementations
- FarmHash64 streaming implementation
- HighwayHash64 streaming implementation

### Changed
- Updated NuGet package configuration
- License changed to Unlicense

## [1.0.0] - 2025-01-17

### Added
- Initial release
- MurmurHash3 (32-bit and 128-bit) streaming implementations
- SipHash-2-4 streaming implementation
- SpookyHash V2 streaming implementation
- Core streaming hash infrastructure
- Comprehensive test suite

[1.6.2]: https://github.com/TheAnsarya/StreamHash/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/TheAnsarya/StreamHash/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/TheAnsarya/StreamHash/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/TheAnsarya/StreamHash/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/TheAnsarya/StreamHash/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/TheAnsarya/StreamHash/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/TheAnsarya/StreamHash/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/TheAnsarya/StreamHash/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/TheAnsarya/StreamHash/releases/tag/v1.0.0
