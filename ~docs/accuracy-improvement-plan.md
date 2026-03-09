# StreamHash Accuracy & Test Coverage Improvement Plan

## Current Test Coverage

- **788+ tests** across 25+ test files
- Individual algorithm tests with known vectors
- Batch streaming tests
- Known value validation tests
- Cross-reference tests against BouncyCastle

## Identified Coverage Gaps

### Priority 1: Comprehensive Test Vectors for All 70 Algorithms

**Gap:** Not all algorithms have authoritative test vectors.

**Plan by category:**

#### Checksums (9 algorithms)

- CRC32: RFC 3720 test vectors + custom edge cases
- CRC32C: RFC 3720 iSCSI test vectors
- CRC64: ECMA-182 reference vectors
- Adler-32: RFC 1950 test vectors
- Fletcher-16/32: Original Fletcher paper vectors
- CRC16 variants: ITU-T reference vectors

#### Fast Non-Crypto (21 algorithms)

- xxHash family: Reference C implementation test vectors
- MurmurHash3: SMHasher suite vectors
- CityHash64/128: Google's reference implementation vectors
- FarmHash64: Google's reference vectors
- SpookyHash: Bob Jenkins' reference vectors
- SipHash-2-4: Official SipHash paper vectors
- HighwayHash64: Google's reference test vectors
- MetroHash64/128: J. Andrew Rogers' reference vectors
- wyhash64: wyhash reference implementation vectors
- FNV-1a/DJB2/SDBM: Well-known test string vectors

#### Cryptographic (25 algorithms)

- MD2/MD4/MD5: RFC 1319/1320/1321 test vectors
- SHA-0: Historical reference implementation vectors
- SHA-1/224/256/384/512: NIST FIPS 180-4 comprehensive vectors
- SHA-512/224, SHA-512/256: NIST SP 800-185 vectors
- SHA3 family: NIST FIPS 202 test vectors (exhaustive)
- Keccak-256/512: Keccak team reference vectors
- BLAKE-256/512: BLAKE specification vectors
- BLAKE2b/2s: Official BLAKE2 reference vectors
- BLAKE3: Official BLAKE3 reference vectors
- RIPEMD-128/160/256/320: RIPE consortium test vectors

#### Other Crypto (15 algorithms)

- Whirlpool: ISO 10118-3 reference vectors
- Tiger-192: Original Tiger paper vectors
- GOST R 34.11-94: Russian standard test vectors
- Streebog-256/512: GOST R 34.11-2012 official vectors
- Skein-256/512/1024: Skein specification appendix vectors
- Groestl-256/512: Groestl submission test vectors
- JH-256/512: JH specification test vectors
- KangarooTwelve: XKCP reference vectors
- SM3: Chinese GB/T 32905-2016 standard vectors

### Priority 2: Streaming Consistency Verification

**Gap:** Limited testing that streaming produces identical results to one-shot.

**Plan:** For each of 70 algorithms, verify:

1. One-shot `ComputeHash(fullData)` matches streaming result
2. Multiple chunk sizes produce identical results (1, 7, 63, 64, 65, 1023, 1024, 1025 bytes)
3. Single byte at a time produces same result
4. Alternating chunk sizes (3, 7, 64, 1) produce same result

### Priority 3: Batch API Consistency

**Gap:** Batch `CreateAllStreaming()` results could theoretically differ from individual streaming.

**Plan:**

1. Compare batch results with individual streaming for all 70 algorithms
2. Test data sizes: empty, 1 byte, 100 bytes, 10KB, 1MB
3. Verify algorithm name mapping is complete and correct

### Priority 4: Edge Case Coverage

**Tests to add:**

- Empty data (0 bytes) for all 70 algorithms
- Single byte (0x00, 0x01, 0x7f, 0x80, 0xff) for all 70
- Buffer boundary sizes (algorithm block sizes +/- 1)
- Extremely large inputs (>4GB for int32 overflow in length counters)
- Concurrent hashing (thread safety verification)
- Reset() and reuse verification for all algorithms

### Priority 5: Golden Reference File

**Plan:** Create a reference data set:

- 5 reference inputs (empty, "abc", "Hello, World!", 1MB random, specific binary pattern)
- Pre-compute all 70 algorithm hashes for each input
- Store as `tests/StreamHash.Core.Tests/ReferenceData/golden-hashes.json`
- Any test failure = immediate regression detection

## Acceptance Criteria

1. Every algorithm has >= 3 authoritative test vectors
2. Streaming consistency verified for all 70 algorithms with 4+ chunk sizes
3. Batch API produces identical results to individual streaming for all 70
4. Golden reference file covers all 70 algorithms
5. Edge cases validated for buffer boundaries and extreme sizes
