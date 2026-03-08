# Reference Hash Values

This document describes the canonical test data and reference hash values used for StreamHash algorithm verification.

## Canonical Seed

All test data is generated using a deterministic seed:

| Property | Value | Description |
|----------|-------|-------------|
| Canonical Seed | `0x5472_6565_4861_7368` | ASCII representation of "TreeHash" |
| Seed as Int32 | `0x1c13160d` | XOR of upper/lower 32 bits (unchecked) |

The seed ensures reproducible test data across all platforms and environments.

## Test File Sizes

| Name | Size (bytes) | Description |
|------|-------------|-------------|
| **64 KB** | 65,536 | Standard small file (exactly 64 KiB) |
| **69 KB** | 70,656 | Odd size (69 × 1024) |
| **767 KB** | 785,408 | Medium file (~767 KiB) |
| **3 MB** | 3,145,728 | Larger file (exactly 3 MiB) |
| **38.3 MB** | 40,160,051 | Prime number size for edge case testing |
| **100 MB** | 104,857,600 | *Future: Large file testing* |
| **212 MB** | 222,298,112 | *Future: Very large file* |
| **765 MB** | 802,160,640 | *Future: Stress testing* |
| **1.37 GB** | 1,471,341,568 | *Future: Memory limit testing* |

## File Generation

Test files are generated using `System.Random` with the canonical seed:

```csharp
var random = new Random(SeedAsInt);
var data = new byte[size];
random.NextBytes(data);
```

The first 16 bytes of the 64 KB file are: `831f52c7d182b24d07a24762e95399dc`

## Reference Sources

Hash values were generated using multiple authoritative sources:

| Source | Algorithms |
|--------|------------|
| **.NET Built-in** | MD5, SHA1, SHA256, SHA384, SHA512, SHA224, SHA512/224, SHA512/256, SHA3-* |
| **BouncyCastle** | MD2, MD4, BLAKE2, RIPEMD, Whirlpool, Tiger, GOST, Streebog, Skein, SM3, Keccak |
| **System.IO.Hashing** | CRC32, CRC64, xxHash32/64/3/128 |
| **StreamHash Native** | Groestl, JH |

## Using Reference Values

Access reference hash values via the `ReferenceHashValues` class:

```csharp
using StreamHash.Core.Testing;

// Get reference hash for 64 KB file
string expected = ReferenceHashValues.KB64.SHA256;

// Generate test data
byte[] testData = TestDataGenerator.File64KB;

// Hash and compare
var hasher = new Sha256StreamingHash();
hasher.Update(testData);
string actual = hasher.FinalizeToHex();

Assert.Equal(expected, actual);
```

## 64 KB Reference Hashes

The following are verified hash values for the 64 KB (65,536 byte) test file:

### Cryptographic Hashes

| Algorithm | Hash Value |
|-----------|------------|
| MD5 | `223474596ee4af6412b67f1eef72deb3` |
| SHA1 | `1068f94a42a1b5d3df34f540546732e5a002b8b8` |
| SHA256 | `2581950a168ed6b18d842c73d3e80deb01665624ce722e0b17f351bf0c586c9b` |
| SHA384 | `6f35eb55bb96cedf10cdf35b02d250a94e0c59a20fd9f830c39b61ddaa4c1b6a...` |
| SHA512 | `8244961409a611d715e233be18199f7a3b9a479cc49bd4afdf5c7108cf7e2e7d...` |
| SHA3-256 | `6ccd7b75522e21a5ee4e424c2f1b785c72b25294036afd43176ff917d5139707` |
| BLAKE2b-256 | `a1643e3365fa5dcc62a828dbaf492a03eb13df47e115b841fe24d5080262dce7` |
| Whirlpool | `041915e00e2338f59c10bb67dfb9b2d0539a89e84c82f1021aa7882c54b7cb6e...` |

### Non-Cryptographic Hashes

| Algorithm | Hash Value |
|-----------|------------|
| CRC32 | `8410504d` |
| CRC64 | `ab2a2ba09859a833` |
| xxHash32 | `469e6e66` |
| xxHash64 | `bee9509751bf7e40` |
| xxHash3 | `a9055f159bb72164` |
| xxHash128 | `4feefdb7334a45fba9055f159bb72164` |

### StreamHash Native

| Algorithm | Hash Value |
|-----------|------------|
| Groestl-256 | `7cd45edd52e221ed580285a107c04516cfd510c4fa395c8f12bef4eee6126ed2` |
| Groestl-512 | `94281f9b71a4de591a6b7a99933eafc7e698f6ada4128857279b4c72c69622330...` |
| JH-256 | `8a7149e74a20975db32f35105f0b9bc47a98ee94fc8a7920ab362d84b207c395` |
| JH-512 | `586c269061f1b1989f9c976a315b77cecc5242b5fc7c68f1b370f57c71609fdd...` |

## Full Reference Values

For complete hash values for all file sizes, see:

- [ReferenceHashValues.cs](../src/StreamHash.Core/Testing/ReferenceHashValues.cs)

## Regenerating Reference Values

To regenerate reference hash values (e.g., after fixing a bug in the reference implementation):

```bash
dotnet test --filter "GenerateReferenceHashes" --logger "console;verbosity=detailed"
```

This runs tests that output hash values for each file size in a format ready to paste into `ReferenceHashValues.cs`.

## Version History

- **2025-07-14**: Initial reference values generated for 64KB, 69KB, 767KB, 3MB, 38.3MB files
