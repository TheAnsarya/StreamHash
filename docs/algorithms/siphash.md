# SipHash Algorithm Documentation

## Overview

SipHash is a family of pseudorandom functions (PRFs) designed by Jean-Philippe Aumasson and Daniel J. Bernstein in 2012. Unlike most non-cryptographic hash functions, SipHash provides cryptographic security guarantees when used with a secret key.

## Variants

| Variant | Compression Rounds | Finalization Rounds | Output |
|---------|-------------------|---------------------|--------|
| SipHash-2-4 | 2 | 4 | 64 bits |
| SipHash-4-8 | 4 | 8 | 64 bits |
| SipHash-1-3 | 1 | 3 | 64 bits |

StreamHash implements **SipHash-2-4**, the recommended default variant.

## Security Properties

### PRF Security
When the 128-bit key is secret and uniformly random, SipHash output is computationally indistinguishable from random. This is stronger than just collision resistance.

### Hash-Flooding Resistance
SipHash was specifically designed to protect hash tables against algorithmic complexity attacks (hash-flooding DoS). Without knowledge of the key, an attacker cannot craft inputs that collide.

### MAC Security
SipHash can be used as a Message Authentication Code (MAC) with security level ~64 bits (birthday bound considerations).

## Algorithm Details

### Initialization

The 128-bit key (k0, k1) initializes four 64-bit state words:

```
v0 = k0 ^ 0x736f6d6570736575  ("somepseu")
v1 = k1 ^ 0x646f72616e646f6d  ("dorandom")
v2 = k0 ^ 0x6c7967656e657261  ("lygenera")
v3 = k1 ^ 0x7465646279746573  ("tedbytes")
```

### SipRound

One round of mixing (the core operation):

```
v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32)
v2 += v3; v3 = rotl(v3, 16); v3 ^= v2
v0 += v3; v3 = rotl(v3, 21); v3 ^= v0
v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32)
```

### Block Processing

For each 8-byte block m:
```
v3 ^= m
SipRound() × cRounds (2 for SipHash-2-4)
v0 ^= m
```

### Finalization

1. Construct final block with length in high byte:
   ```
   b = (len mod 256) << 56
   b |= remaining bytes (1-7 bytes padded)
   ```

2. Process final block:
   ```
   v3 ^= b
   SipRound() × cRounds
   v0 ^= b
   ```

3. XOR marker and final rounds:
   ```
   v2 ^= 0xff
   SipRound() × dRounds (4 for SipHash-2-4)
   ```

4. Return result:
   ```
   return v0 ^ v1 ^ v2 ^ v3
   ```

## Properties

### Speed
- ~2-4 GB/s on modern 64-bit CPUs
- Optimized for short messages (hash table keys)
- Competitive with non-cryptographic hashes for medium inputs

### Key Requirements
- Must be 128 bits (16 bytes)
- Should be generated with a cryptographically secure RNG
- Same key always produces same hash for same input

### Output Distribution
- Uniform distribution over 64-bit output space
- All bits equally likely to be 0 or 1

## Use Cases

### Ideal For
1. **Hash table protection**: Primary use case
   ```csharp
   var key = RandomNumberGenerator.GetBytes(16);
   var hasher = new SipHash24(key);
   ```

2. **Network packet authentication**: Short MACs
   ```csharp
   ulong tag = SipHash24.Hash(packet, secretKey);
   ```

3. **Cookie integrity**: Web session tokens
   ```csharp
   ulong cookieMAC = SipHash24.Hash(cookieData, serverKey);
   ```

### Not Ideal For
- Password hashing (use Argon2, bcrypt, scrypt)
- Long-term signatures (use HMAC-SHA256+)
- When 128+ bit security is required

## Streaming Implementation Notes

### State Preservation
The streaming implementation maintains:
- `v0, v1, v2, v3`: Current state vectors
- `k0, k1`: Original key for reset
- Internal buffer for partial blocks

### Length Encoding
The total message length is encoded in the final block's high byte. The streaming implementation tracks `TotalBytesProcessed` for this purpose.

## Test Vectors

From the official SipHash paper (Appendix A):

**Key:** `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f`

| Message Length | Message | Expected Hash |
|----------------|---------|---------------|
| 0 | (empty) | 310e0edd47db6f72 |
| 1 | 00 | 7c2d71c93a4e4f0e |
| 2 | 00 01 | d5b5e7c4e3b9f6d2 |
| 15 | 00..0e | a129ca6149be45e5 |

## Security Considerations

### Key Management
- Generate keys with `RandomNumberGenerator.GetBytes(16)`
- Don't reuse keys across different security domains
- Rotate keys periodically in long-running applications

### Timing Attacks
SipHash is designed to be constant-time. The StreamHash implementation:
- Uses only data-independent branches
- Avoids early exits based on input content
- Uses constant-time rotations

### Known Attacks
- No practical attacks against SipHash-2-4 are known
- SipHash-1-2 (fewer rounds) has theoretical weaknesses
- 64-bit output limits security to ~32 bits against birthday attacks

## Comparison with Other Hash Functions

| Property | SipHash | MurmurHash3 | xxHash |
|----------|---------|-------------|--------|
| Keyed | ✅ Yes | ❌ Seed only | ❌ Seed only |
| PRF Security | ✅ Yes | ❌ No | ❌ No |
| Hash-flooding Safe | ✅ Yes | ❌ No | ❌ No |
| Speed (short) | Good | Excellent | Excellent |
| Speed (long) | Good | Excellent | Excellent |

## References

1. [SipHash Official Website](https://131002.net/siphash/)
2. [SipHash Paper (PDF)](https://www.aumasson.jp/siphash/siphash.pdf)
3. [Reference Implementation (C)](https://github.com/veorq/SipHash)
4. [Wikipedia - SipHash](https://en.wikipedia.org/wiki/SipHash)
5. [Hash-flooding Attack Paper](https://events.ccc.de/congress/2011/Fahrplan/attachments/2007_28C3_Effective_DoS_on_web_application_platforms.pdf)
