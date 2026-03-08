# MurmurHash3 Algorithm Documentation

## Overview

MurmurHash3 is a non-cryptographic hash function created by Austin Appleby in 2008. It is the successor to MurmurHash2 and provides excellent distribution, speed, and avalanche properties.

## Variants

| Variant | Output Size | Block Size | Optimized For |
|---------|-------------|------------|---------------|
| MurmurHash3_x86_32 | 32 bits | 4 bytes | 32-bit platforms |
| MurmurHash3_x86_128 | 128 bits | 16 bytes | 32-bit platforms |
| MurmurHash3_x64_128 | 128 bits | 16 bytes | 64-bit platforms |

StreamHash implements:

- `MurmurHash3_32` (x86_32 variant)
- `MurmurHash3_128` (x64_128 variant, recommended for 64-bit)

## Algorithm Details

### MurmurHash3-32

**Constants:**

```
c1 = 0xcc9e2d51
c2 = 0x1b873593
```

**Block Processing:**

```
for each 4-byte block:
    k1 = block as uint32
    k1 *= c1
    k1 = rotl32(k1, 15)
    k1 *= c2
    
    h1 ^= k1
    h1 = rotl32(h1, 13)
    h1 = h1 * 5 + 0xe6546b64
```

**Tail Handling (1-3 bytes):**

```
k1 = 0
switch(len & 3):
    case 3: k1 ^= tail[2] << 16
    case 2: k1 ^= tail[1] << 8
    case 1: k1 ^= tail[0]
            k1 *= c1
            k1 = rotl32(k1, 15)
            k1 *= c2
            h1 ^= k1
```

**Finalization (fmix32):**

```
h1 ^= len
h1 ^= h1 >> 16
h1 *= 0x85ebca6b
h1 ^= h1 >> 13
h1 *= 0xc2b2ae35
h1 ^= h1 >> 16
return h1
```

### MurmurHash3-128 (x64)

**Constants:**

```
c1 = 0x87c37b91114253d5
c2 = 0x4cf5ad432745937f
```

**Block Processing:**

```
for each 16-byte block:
    k1 = block[0..8] as uint64
    k2 = block[8..16] as uint64
    
    k1 *= c1; k1 = rotl64(k1, 31); k1 *= c2; h1 ^= k1
    h1 = rotl64(h1, 27); h1 += h2; h1 = h1 * 5 + 0x52dce729
    
    k2 *= c2; k2 = rotl64(k2, 33); k2 *= c1; h2 ^= k2
    h2 = rotl64(h2, 31); h2 += h1; h2 = h2 * 5 + 0x38495ab5
```

**Finalization (fmix64):**

```
k ^= k >> 33
k *= 0xff51afd7ed558ccd
k ^= k >> 33
k *= 0xc4ceb9fe1a85ec53
k ^= k >> 33
return k
```

## Properties

### Avalanche Effect

Every bit of input affects every bit of output. The finalization mix ensures good avalanche even for inputs that differ by only one bit.

### Speed

- MurmurHash3-32: ~3-5 GB/s on modern CPUs
- MurmurHash3-128: ~5-7 GB/s on 64-bit CPUs

### Collision Resistance

- 32-bit: Expected collision after ~65,536 unique inputs (birthday bound)
- 128-bit: Practically collision-free for most applications

### NOT Cryptographically Secure

MurmurHash3 is vulnerable to:

- Preimage attacks
- Collision attacks with adversarial input
- Hash-flooding attacks (use SipHash for hash tables with untrusted keys)

## Use Cases

### Good For

- Hash tables and hash maps
- Bloom filters
- Data partitioning/sharding
- Content-addressable storage
- Deduplication
- Checksums (non-security critical)

### Not Good For

- Password hashing (use Argon2, bcrypt)
- Digital signatures (use SHA-256+)
- Message authentication (use HMAC or SipHash)
- Security-sensitive hash tables (use SipHash)

## Streaming Implementation Notes

### State Management

The streaming implementation maintains:

- `_h1` (and `_h2` for 128-bit): Accumulated hash state
- `_seed`: Original seed for reset
- Internal buffer for partial blocks

### Consistency Guarantee

```csharp
// These produce identical results:
uint oneShot = MurmurHash3_32.Hash(data, seed);

using var stream = new MurmurHash3_32(seed);
stream.Update(data[0..10]);
stream.Update(data[10..20]);
stream.Update(data[20..]);
uint streamed = stream.Finalize();

Assert.Equal(oneShot, streamed);
```

## Test Vectors

### MurmurHash3-32

| Input | Seed | Expected Hash |
|-------|------|---------------|
| (empty) | 0 | 0x00000000 |
| (empty) | 1 | 0x514e28b7 |
| 0x21 | 0 | 0x72661cf4 |
| "Hello" | 0 | 0x96e4ca2f |

### Reference Implementation

The canonical implementation is in the [SMHasher repository](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp).

## References

1. [SMHasher - Original MurmurHash Repository](https://github.com/aappleby/smhasher)
2. [Wikipedia - MurmurHash](https://en.wikipedia.org/wiki/MurmurHash)
3. [MurmurHash3 Algorithm Specification](https://github.com/aappleby/smhasher/wiki/MurmurHash3)
