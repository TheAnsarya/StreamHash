# HighwayHash

## Overview

HighwayHash is a fast, keyed hash function designed by Google for 64-bit CPUs. It combines high speed with strong avalanche properties and resistance to hash-flooding attacks.

## Algorithm Details

### HighwayHash64

- **Output Size:** 64 bits (8 bytes)
- **Key Size:** 256 bits (4 × 64-bit values)
- **Block Size:** 32 bytes
- **Design:** SIMD-first architecture

## Key Features

| Feature | Description |
|---------|-------------|
| **Keyed** | Requires 256-bit secret key |
| **DoS Resistant** | Hash-flooding protection |
| **High Speed** | 10+ GB/s with SIMD |
| **Strong Avalanche** | Excellent bit mixing |
| **Portable** | Scalar fallback available |

## Architecture

HighwayHash uses a 4-lane SIMD design:

```
┌─────────────────────────────────────────┐
│              256-bit State              │
├──────────┬──────────┬─────────┬─────────┤
│  Lane 0  │  Lane 1  │  Lane 2 │  Lane 3 │
│  64-bit  │  64-bit  │  64-bit │  64-bit │
└──────────┴──────────┴─────────┴─────────┘
```

### State Vectors

```csharp
private readonly ulong[] _v0 = new ulong[4];   // Primary state
private readonly ulong[] _v1 = new ulong[4];   // Secondary state
private readonly ulong[] _mul0 = new ulong[4]; // Multiplier 0
private readonly ulong[] _mul1 = new ulong[4]; // Multiplier 1
```

### Initialization

```csharp
// Initial multipliers (magic constants)
_mul0[0] = 0xdbe6d5d5fe4cce2fUL;
_mul0[1] = 0xa4093822299f31d0UL;
_mul0[2] = 0x13198a2e03707344UL;
_mul0[3] = 0x243f6a8885a308d3UL;

// v0 initialized from key XOR mul0
_v0[i] = _mul0[i] ^ _key[i];

// v1 initialized from rotated key XOR mul1
_v1[i] = _mul1[i] ^ ((_key[i] >> 32) | (_key[i] << 32));
```

## Block Processing

Each 32-byte block is processed as 4 lanes:

### Update Function

```csharp
// Add packet to v1
_v1[i] += packet[i];
_v1[i] += _mul0[i];

// Update multipliers
_mul0[i] ^= (_v1[i] & 0xffffffffUL) * (_v0[i] >> 32);

// Update v0
_v0[i] += _mul1[i];
_mul1[i] ^= (_v0[i] & 0xffffffffUL) * (_v1[i] >> 32);

// ZipperMerge for lane mixing
_v0[i] += ZipperMerge(_v1);
_v1[i] += ZipperMerge(_v0);
```

### ZipperMerge

A novel mixing operation that interleaves bytes from two 64-bit values:

```csharp
private static ulong ZipperMerge0(ulong v1, ulong v0) {
    return (((v0 & 0xff000000UL) | (v1 & 0xff00000000UL)) >> 24) |
           (((v0 & 0xff0000000000UL) | (v1 & 0xff000000000000UL)) >> 16) |
           (v0 & 0xff0000UL) |
           ((v0 & 0xff00UL) << 32) |
           ((v1 & 0xff00000000000000UL) >> 8) |
           (v0 << 56);
}
```

## Usage Example

```csharp
using StreamHash.Core;

// With default key (NOT secure for production)
using var hasher = new HighwayHash64();
hasher.Update(data);
ulong hash = hasher.Finalize();

// With custom 256-bit key (RECOMMENDED)
ulong[] secretKey = [
    0x0706050403020100UL,
    0x0f0e0d0c0b0a0908UL,
    0x1716151413121110UL,
    0x1f1e1d1c1b1a1918UL
];
using var secureHasher = new HighwayHash64(secretKey);
secureHasher.Update(data);
ulong secureHash = secureHasher.Finalize();

// Key from byte array
byte[] keyBytes = new byte[32];
RandomNumberGenerator.Fill(keyBytes);
using var byteKeyHasher = new HighwayHash64(keyBytes);
```

## Security Properties

### DoS Resistance

With a secret key, HighwayHash provides:
- **Unpredictable output** for unknown key
- **Collision resistance** against adversarial inputs
- **Protection** against hash-flooding attacks

### Limitations

⚠️ **NOT a cryptographic hash**
- Not suitable for digital signatures
- Not suitable for password hashing
- Not suitable for message authentication (use HMAC)

## Performance

| Platform | Throughput |
|----------|------------|
| AVX2 (SIMD) | ~15 GB/s |
| SSE4.1 | ~10 GB/s |
| Scalar fallback | ~3 GB/s |

This implementation provides the scalar fallback for maximum portability.

## When to Use HighwayHash

✅ **Good for:**
- Network packet hashing (with secret key)
- Load balancing (DoS protection)
- High-throughput data processing
- SipHash replacement (higher speed)

❌ **Not suitable for:**
- Cryptographic purposes
- Password storage
- Digital signatures

## References

- [HighwayHash - Google's Official Repository](https://github.com/google/highwayhash)
- [HighwayHash: Fast, Strong, Keyed Hash Function (arXiv)](https://arxiv.org/abs/1612.06257)
- [HighwayHash Design Paper](https://github.com/google/highwayhash/blob/master/README.md)

## License

HighwayHash is released under the Apache 2.0 License by Google.
