# Changelog

All notable changes to StreamHash will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.11.2] - 2026-03-18

### Changed

- Fixed benchmark chunk sizes to use realistic I/O buffer sizes (#84)
	- BasicHashesBenchmarks: Replaced 16MB chunks (larger than 10MB test data) with 1MB chunks
	- Added chunked streaming variants for all file sizes (1MB, 10MB, 100MB)
- StreamingChunkBenchmarks: Expanded from 1 file size to 3 (16KB, 1MB, 10MB) and added 256KB/1MB chunk sizes
	- Added Basic4 and All70 multi-hash streaming benchmarks

### Added

- ChunkSizeMatrixBenchmarks: Full file-size x chunk-size benchmark matrix
	- Tests 6 file sizes (16KB-100MB) x 7 chunk sizes (4KB-4MB) for both Basic4 and All70
	- ChunkSizeQuickBenchmarks: Focused quick benchmark for key combinations

## [1.11.1] - 2026-03-17

### Added

- NuGet package icon (128x128 PNG — blue-to-teal gradient with hash symbol)
- CI build status badge on README
- NuGet version and downloads badges on README
- Code coverage collection with Coverlet/Cobertura in CI workflow
- Coverage summary posted as PR comments via CodeCoverageSummary
- Explicit `permissions: contents: write` on release workflow
- `NUGET_API_KEY` GitHub secret for automated NuGet publishing

## [1.11.0] - 2026-03-16

### Performance

- **Keccak/SHA-3 Full Round Unrolling** — 6 algorithms improved (#66)
	- SHA3-224: 1.63x → 0.95x (now faster than BouncyCastle)
	- SHA3-256: 1.50x → 1.03x (at parity)
	- SHA3-384: 1.53x → 1.06x (at parity)
	- SHA3-512: 1.49x → 1.02x (at parity)
	- Keccak-256: 1.52x → 1.02x (at parity)
	- Keccak-512: 1.49x → 1.03x (at parity)
	- 24 rounds fully inlined with constants, eliminating loop overhead
- **BLAKE2b/2s Optimization** — Vector-based message loading (#72, #73)
	- BLAKE2b: 1.59x → 1.14x vs BouncyCastle (AVX2 vector loading)
	- BLAKE2s: 1.61x → 1.05x vs BouncyCastle (near parity)
- **RIPEMD-128 Full Unrolling** — 1.8x FASTER than BouncyCastle (#77)
	- Ratio: 1.05x → 0.56x — fully unrolled 64 rounds with inline constants
- **xxHash One-Shot API** — Eliminated streaming overhead (#75)
	- xxHash32: 1.95x → 0.99x (at parity with System.IO.Hashing)
	- xxHash3: 1.04x → 0.99x (at parity)
	- xxHash128: 1.05x → 0.98x (faster)
	- Detects full-data one-shot calls, routes to `HashToUInt64()`/`Hash()` static APIs
- **SHA-512/256 ReadOnlySpan K Constants** — (#76)
	- Ratio: 0.99x → 0.91x — `ReadOnlySpan<byte>` K constants avoid array loads
- **HighwayHash64 Safe Refactor** — Eliminated true unsafe code (#70)
	- Replaced `unsafe` pointer operations with `Unsafe.As<>()` and `Unsafe.ReadUnaligned<>()`
	- All tests pass, no performance regression
- **CRC-32C Hardware Acceleration** — SSE4.2 CRC32C instruction
	- Processes 8 bytes per instruction via `Sse42.X64.Crc32()`
	- 256-entry lookup table fallback for non-SSE4.2 CPUs

### Added

- **VeryLargeFileBenchmarks** — New benchmark class for 10MB, 100MB, and 1GB data (#79)
	- 44 comparison benchmarks across all major algorithm families
	- All 132 benchmarks completed across 21 algorithms
	- Key findings: Whirlpool 4-5x faster at all sizes, SHA-1 advantage grows to 2.9x at 1GB, xxHash128 reverses to 1.4x faster at 1GB
	- Full results in [benchmarks.md](../docs/benchmarks.md#very-large-file-benchmarks-10-mb-100-mb-1-gb)

### Summary

- 20 algorithms faster than reference libraries (up from 18)
- 10 algorithms at parity (up from 8)
- Only 2 algorithms slower: BLAKE2b (1.14x), xxHash64 (1.25x — byte order overhead)
- BLAKE3 at parity with Rust native (was 15.70x slower)

## [1.10.0] - 2026-02-10

### Added

- **🎯 Basic Hashes API** - Optimized for common use case (#new)
 	- `HashFacade.CreateBasicHashesStreaming()` - Specialized method for CRC32, MD5, SHA-1, SHA-256
 	- Perfect for file verification, download validation, archive checksums
 	- ~17.5x faster than `CreateAllStreaming()` when you only need these 4 algorithms
 	- Comprehensive test coverage (3 new unit tests)
 	- Performance benchmarks comparing Basic vs All algorithms
- **🔑 HashAlgorithmNames Constants** - Type-safe algorithm name constants
 	- 70 public constants for all algorithm names (e.g., `HashAlgorithmNames.Sha256`)
 	- Helper arrays: `BasicHashes`, `Checksums`, `FastNonCrypto`, `Cryptographic`, `All`
 	- Eliminates magic strings, enables IntelliSense, prevents typos
 	- All internal code updated to use constants
- **🔧 All-Native Implementations** - Removed ALL external hash library dependencies (#52)
 	- All 70 algorithms now implemented in pure C# — no BouncyCastle, Blake3, Blake2Fast, or acryptohashnet
 	- Only remaining dependency: `System.IO.Hashing` (Microsoft BCL, for CRC/xxHash acceleration)
 	- Removed 3 NuGet packages: acryptohashnet, Blake3, SauceControl.Blake2Fast
 	- 10 algorithms rewritten natively: BLAKE2b, BLAKE2s, BLAKE-256, BLAKE-512, BLAKE3, Keccak-256, Keccak-512, RIPEMD-128, RIPEMD-160, Tiger-192
- **📊 Comparison Benchmarks** - Side-by-side performance vs external libraries (#53)
 	- ComparisonBenchmarks.cs: 33 crypto algorithm comparisons vs BouncyCastle, acryptohashnet, Blake2Fast, Blake3, dotSHA3
 	- NonCryptoComparisonBenchmarks.cs: 8 non-crypto comparisons vs System.IO.Hashing, HashDepot
 	- Performance benchmark documentation at docs/benchmarks.md

### Changed

- Batch streaming APIs now use `HashAlgorithmNames` constants internally
- Documentation examples updated to demonstrate constant usage
- README rewritten to reflect all-native architecture, no external hash dependencies
- Acknowledgments section updated to reference-only (libraries are no longer runtime dependencies)

### Performance

- **BLAKE2b**: 3.9x faster (6.29x → 1.62x vs BouncyCastle) via fully unrolled compression rounds (#56)
- **BLAKE2s**: 4.2x faster (7.01x → 1.68x vs BouncyCastle) via fully unrolled compression rounds (#56)
- Fully unrolled compression eliminates ~768 Span bounds checks per BLAKE2b compress call
- All optimizations use pure safe C# — no unsafe code, no SIMD intrinsics
- Basic hashes streaming: 4 algorithms in ~600μs for 1MB (vs ~10.5ms for all 70)
- Ideal for common scenarios: file integrity, legacy compatibility, corruption detection
- Single memory pass, optimized for standard hash verification workflows

## [1.7.0] - 2026-02-05

### Added

- **🚀 Batch Streaming API** - Major performance feature! (#17)
 	- `IMultiStreamingHashBytes` interface for batch processing multiple algorithms
 	- `HashFacade.CreateAllStreaming()` - Process all 70 algorithms simultaneously
 	- `HashFacade.CreateBatchStreaming()` - Custom algorithm selection
 	- `HashAlgorithmSet` enum - Category-based algorithm filtering
 	- Parallel processing strategy: 8x speedup on 8-core CPUs, 4x on 4-core, 2x on 2-core
 	- Smart threshold: Uses parallel for ≥8 algorithms, sequential for <8 (lower overhead)
- `HashFacade.GetAllAlgorithmNames()` - Returns all 70 algorithm names as string array
- 10 new comprehensive batch API tests (now 762 total tests)

### Changed

- Package description updated to highlight batch streaming support
- Added `batch` and `parallel` package tags for discoverability
- Algorithm count corrected to 70 (was incorrectly documented as 71)

### Performance

- Batch API provides 8-16x speedup for multi-algorithm hashing on multi-core systems
- Single memory pass for all algorithms maximizes cache efficiency
- Automatic parallelization for large hasher counts (≥8 algorithms)

### Fixed

- Documentation now correctly states 70 algorithms (not 71)

## [1.6.3] - 2025-02-04

### Fixed

- All 71 algorithms confirmed working and accessible via HashFacade
- Package tags updated to include FNV, DJB2, SDBM keywords for discoverability

### Verified

- FNV-1a 32/64-bit implementations with correct prime (0x01000193 / 0x00000100000001B3) and offset basis
- DJB2 and DJB2a (XOR variant) with initial value 5381
- SDBM with multiply by 65599 (optimized as x + x<<6 + x<<16)
- LoseLose simple byte sum implementation
- All CRC-16 variants (CCITT, MODBUS, USB, ARC, XMODEM, KERMIT, DNP, MAXIM)
- All 752 tests passing

## [1.6.2] - 2025-02-04

### Added

- Custom high-performance Whirlpool implementation with T-table optimization (#15)
- AES-NI SIMD optimization for Grøstl SubBytes operation (#13)
- SSSE3 SIMD optimization for JH linear transform (#14)
- AVX2/SSE4.1 SIMD optimization for HighwayHash64 (#7)
- GitHub Actions CI/CD workflows for automated testing and releases (#10)
- Bit-sliced S-box implementation for JH

### Changed

- Whirlpool now uses custom T-table implementation instead of BouncyCastle wrapper
- Grøstl MixBytes optimized with T-table lookup
- HighwayHash64 ProcessBlock rewritten with SIMD intrinsics
- All SIMD optimizations include scalar fallbacks for compatibility
- Memory allocations reduced in HighwayHash64 (1.8MB → 360B per hash)

### Performance

- **Whirlpool**: 3.2x faster (52.4ms → 16.5ms for 1MB)
- **Grøstl**: ~2.5x faster (153ms → 61ms for 1MB) with AES-NI
- **JH**: ~1.4x faster (191ms → 137ms for 1MB) with SSSE3
- **HighwayHash64**: ~1.4x faster (1060ms → 756ms for 1MB) with AVX2

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
