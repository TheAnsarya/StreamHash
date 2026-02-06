# BouncyCastle Removal Plan

**Goal:** Eliminate all BouncyCastle dependencies from StreamHash for:
- Reduced package size (~4MB → <1MB)
- Faster startup (no large assembly loading)
- Better performance (native SIMD implementations)
- Zero/low allocations per hash operation

## Current State (v1.8.0+)

### ✅ Already Migrated (18 algorithms)
| Algorithm | Old Source | New Source | Status |
|-----------|------------|------------|--------|
| BLAKE2b/2s | BouncyCastle | SauceControl.Blake2Fast | ✅ Complete |
| BLAKE256/512 | BouncyCastle | SauceControl.Blake2Fast | ✅ Complete |
| BLAKE3 | BouncyCastle | Blake3.NET | ✅ Complete |
| SHA3-224/256/384/512 | BouncyCastle | nebulae.dotSHA3 | ✅ Complete |
| RIPEMD-128/160 | BouncyCastle | acryptohashnet | ✅ Complete |
| Keccak-256/512 | BouncyCastle | acryptohashnet | ✅ Complete |
| Tiger-192 | BouncyCastle | acryptohashnet | ✅ Complete |
| MD2 | BouncyCastle | acryptohashnet | ✅ Complete |
| MD4 | BouncyCastle | acryptohashnet | ✅ Complete |
| SHA-0 | BouncyCastle | acryptohashnet | ✅ Complete |
| SHA-224 | BouncyCastle | acryptohashnet | ✅ Complete |

### ❌ Still on BouncyCastle (10 algorithms)

#### ComputeHash (One-Shot)
| Algorithm | BouncyCastle Type | Alternative |
|-----------|-------------------|-------------|
| MD2 | MD2Digest | acryptohashnet.MD2 |
| MD4 | MD4Digest | acryptohashnet.MD4 |
| SHA-224 | Sha224Digest | Custom impl (SHA-256 truncated) |
| SHA-512/224 | Sha512tDigest(224) | Custom impl (SHA-512 truncated) |
| SHA-512/256 | Sha512tDigest(256) | Custom impl (SHA-512 truncated) |
| RIPEMD-256 | RipeMD256Digest | Custom impl or NSec |
| RIPEMD-320 | RipeMD320Digest | Custom impl |
| GOST-94 | Gost3411Digest | Custom impl |
| Streebog-256 | Gost3411_2012_256Digest | Custom impl |
| Streebog-512 | Gost3411_2012_512Digest | Custom impl |
| Skein-256 | SkeinDigest(256,256) | Custom impl |
| Skein-512 | SkeinDigest(512,512) | Custom impl |
| Skein-1024 | SkeinDigest(1024,1024) | Custom impl |
| SM3 | SM3Digest | Custom impl |

#### CreateStreaming
| Algorithm | BouncyCastle Factory | Alternative |
|-----------|----------------------|-------------|
| MD2 | CreateMd2() | AcryptohashnetFactory |
| MD4 | CreateMd4() | AcryptohashnetFactory |
| SHA-0 | CreateSha0() | Custom impl |
| SHA-224 | CreateSha224() | Custom impl |
| SHA-512/224 | CreateSha512_224() | Custom impl |
| SHA-512/256 | CreateSha512_256() | Custom impl |
| RIPEMD-256 | CreateRipemd256() | Custom impl |
| RIPEMD-320 | CreateRipemd320() | Custom impl |
| GOST-94 | CreateGost94() | Custom impl |
| Streebog-256 | CreateStreebog256() | Custom impl |
| Streebog-512 | CreateStreebog512() | Custom impl |
| Skein-256 | CreateSkein256() | Custom impl |
| Skein-512 | CreateSkein512() | Custom impl |
| Skein-1024 | CreateSkein1024() | Custom impl |
| Groestl-256 | CreateGroestl256() | Custom impl |
| Groestl-512 | CreateGroestl512() | Custom impl |
| JH-256 | CreateJh256() | Custom impl |
| JH-512 | CreateJh512() | Custom impl |
| SM3 | CreateSm3() | Custom impl |

## Migration Strategy

### Phase 1: Easy Wins (acryptohashnet already has these)
- [x] MD2 → acryptohashnet.MD2
- [x] MD4 → acryptohashnet.MD4
- These are already in acryptohashnet, just need to wire them up

### Phase 2: SHA-2 Truncated Variants
- [ ] SHA-224: Compute full SHA-256, truncate to 224 bits
- [ ] SHA-512/224: Compute SHA-512 with modified IV, truncate to 224 bits
- [ ] SHA-512/256: Compute SHA-512 with modified IV, truncate to 256 bits

Implementation approach:
```csharp
// SHA-224 is SHA-256 with different IV and truncated output
public static byte[] ComputeSha224(ReadOnlySpan<byte> data) {
	// Use .NET's SHA256 with modified IV (custom impl required)
	// OR use a wrapper that truncates SHA256 output
}
```

### Phase 3: RIPEMD Extended
- [ ] RIPEMD-256: Needs custom implementation
- [ ] RIPEMD-320: Needs custom implementation

Reference: Original RIPEMD paper and test vectors

### Phase 4: Russian GOST Standards
- [ ] GOST-94 (Gost3411): Custom implementation
- [ ] Streebog-256 (GOST 34.11-2012): Custom implementation  
- [ ] Streebog-512 (GOST 34.11-2012): Custom implementation

These are complex algorithms with S-boxes. Consider:
- Port from BouncyCastle (MIT license compatible)
- Find existing C# implementations

### Phase 5: SHA-3 Competition Finalists
- [ ] Skein-256/512/1024: Custom implementation (Threefish-based)
- [ ] Groestl-256/512: Custom implementation (AES-like)
- [ ] JH-256/512: Custom implementation

These are complex but well-documented. May find existing C# ports.

### Phase 6: Chinese Standard
- [ ] SM3: Custom implementation

SM3 is similar to SHA-256 in structure. Reference implementations available.

## Resources

### Existing Libraries to Evaluate
- **NSec** - Has RIPEMD-256 (not 320)
- **acryptohashnet** - Already using, has MD2/MD4/Haval/Snefru
- **Konscious.Security.Cryptography** - Argon2 but no hashes
- **System.Security.Cryptography** - .NET built-in (limited)

### Reference Implementations
- BouncyCastle C# (MIT) - Can port algorithms
- Crypto++ (Boost) - Reference C++ implementations
- libsodium - Some algorithms available

## Testing Requirements

Each migrated algorithm must:
1. Pass all existing test vectors
2. Produce identical output to BouncyCastle for random data
3. Support streaming (IStreamingHash interface)
4. Have allocation benchmarks (target: <100B per hash)

## Timeline

| Phase | Algorithms | Estimated Effort |
|-------|------------|------------------|
| 1 | MD2, MD4 | 1 hour (already done in acryptohashnet) |
| 2 | SHA-224, SHA-512/t | 2-3 hours |
| 3 | RIPEMD-256/320 | 3-4 hours |
| 4 | GOST-94, Streebog | 4-6 hours |
| 5 | Skein, Groestl, JH | 6-8 hours |
| 6 | SM3 | 2-3 hours |

Total: ~20-26 hours of implementation work

## Success Criteria

- [ ] All 70 algorithms work without BouncyCastle
- [ ] All 762+ tests pass
- [ ] Performance benchmarks show improvement or parity
- [ ] Package size reduced by >80%
- [ ] Zero Gen0/Gen1/Gen2 allocations for large data

