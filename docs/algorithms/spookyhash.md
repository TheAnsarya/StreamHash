# SpookyHash V2 Algorithm Documentation

## Overview

SpookyHash is a non-cryptographic hash function created by Bob Jenkins (author of the famous Jenkins hash functions). Version 2 fixes a weakness in Version 1 and is the recommended version for all uses.

## Characteristics

| Property | Value |
|----------|-------|
| Output Size | 128 bits (or 64-bit truncation) |
| Block Size | 96 bytes (12 × 64-bit words) |
| Speed | ~8-10 GB/s on modern 64-bit CPUs |
| Design Goal | Fast for long messages |

## Algorithm Design

SpookyHash uses different algorithms for short and long messages:

### Short Messages (< 192 bytes)

For messages under 192 bytes, a simpler 4-state algorithm is used:
- State: 4 × 64-bit words (h0, h1, h2, h3)
- Processes 32 bytes at a time
- Different mixing function (ShortMix)

### Long Messages (≥ 192 bytes)

For longer messages:
- State: 12 × 64-bit words (s0 through s11)
- Processes 96 bytes per iteration
- Full mixing function with all 12 state words

## Algorithm Details

### Initialization

**Magic Constant:**
```
SC = 0xdeadbeefdeadbeef (golden ratio)
```

**Long Message Init:**
```
s0 = seed1;  s1 = seed2;  s2 = SC
s3 = seed1;  s4 = seed2;  s5 = SC
s6 = seed1;  s7 = seed2;  s8 = SC
s9 = seed1;  s10 = seed2; s11 = SC
```

**Short Message Init:**
```
h0 = seed1; h1 = seed2
h2 = SC;    h3 = SC
```

### Mix Function (Long Messages)

The full mixing processes 96 bytes (12 words) per iteration:

```
s0 += data[0];  s2 ^= s10; s11 ^= s0;  s0 = rotl(s0, 11);  s11 += s1
s1 += data[1];  s3 ^= s11; s0 ^= s1;   s1 = rotl(s1, 32);  s0 += s2
s2 += data[2];  s4 ^= s0;  s1 ^= s2;   s2 = rotl(s2, 43);  s1 += s3
s3 += data[3];  s5 ^= s1;  s2 ^= s3;   s3 = rotl(s3, 31);  s2 += s4
s4 += data[4];  s6 ^= s2;  s3 ^= s4;   s4 = rotl(s4, 17);  s3 += s5
s5 += data[5];  s7 ^= s3;  s4 ^= s5;   s5 = rotl(s5, 28);  s4 += s6
s6 += data[6];  s8 ^= s4;  s5 ^= s6;   s6 = rotl(s6, 39);  s5 += s7
s7 += data[7];  s9 ^= s5;  s6 ^= s7;   s7 = rotl(s7, 57);  s6 += s8
s8 += data[8];  s10 ^= s6; s7 ^= s8;   s8 = rotl(s8, 55);  s7 += s9
s9 += data[9];  s11 ^= s7; s8 ^= s9;   s9 = rotl(s9, 54);  s8 += s10
s10 += data[10]; s0 ^= s8; s9 ^= s10;  s10 = rotl(s10, 22); s9 += s11
s11 += data[11]; s1 ^= s9; s10 ^= s11; s11 = rotl(s11, 46); s10 += s0
```

### ShortMix (Short Messages)

```
h2 = rotl(h2, 50);  h2 += h3;  h0 ^= h2
h3 = rotl(h3, 52);  h3 += h0;  h1 ^= h3
h0 = rotl(h0, 30);  h0 += h1;  h2 ^= h0
h1 = rotl(h1, 41);  h1 += h2;  h3 ^= h1
h2 = rotl(h2, 54);  h2 += h3;  h0 ^= h2
h3 = rotl(h3, 48);  h3 += h0;  h1 ^= h3
h0 = rotl(h0, 38);  h0 += h1;  h2 ^= h0
h1 = rotl(h1, 37);  h1 += h2;  h3 ^= h1
h2 = rotl(h2, 62);  h2 += h3;  h0 ^= h2
h3 = rotl(h3, 34);  h3 += h0;  h1 ^= h3
h0 = rotl(h0, 5);   h0 += h1;  h2 ^= h0
h1 = rotl(h1, 36);  h1 += h2;  h3 ^= h1
```

### End Partial (Finalization)

Applied 3 times at the end of long messages:

```
s11 += s1;  s2 ^= s11;  s1 = rotl(s1, 44)
s0 += s2;   s3 ^= s0;   s2 = rotl(s2, 15)
s1 += s3;   s4 ^= s1;   s3 = rotl(s3, 34)
s2 += s4;   s5 ^= s2;   s4 = rotl(s4, 21)
s3 += s5;   s6 ^= s3;   s5 = rotl(s5, 38)
s4 += s6;   s7 ^= s4;   s6 = rotl(s6, 33)
s5 += s7;   s8 ^= s5;   s7 = rotl(s7, 10)
s6 += s8;   s9 ^= s6;   s8 = rotl(s8, 13)
s7 += s9;   s10 ^= s7;  s9 = rotl(s9, 38)
s8 += s10;  s11 ^= s8;  s10 = rotl(s10, 53)
s9 += s11;  s0 ^= s9;   s11 = rotl(s11, 42)
s10 += s0;  s1 ^= s10;  s0 = rotl(s0, 54)
```

### ShortEnd (Short Finalization)

```
h3 ^= h2;  h2 = rotl(h2, 15);  h3 += h2
h0 ^= h3;  h3 = rotl(h3, 52);  h0 += h3
h1 ^= h0;  h0 = rotl(h0, 26);  h1 += h0
h2 ^= h1;  h1 = rotl(h1, 51);  h2 += h1
h3 ^= h2;  h2 = rotl(h2, 28);  h3 += h2
h0 ^= h3;  h3 = rotl(h3, 9);   h0 += h3
h1 ^= h0;  h0 = rotl(h0, 47);  h1 += h0
h2 ^= h1;  h1 = rotl(h1, 54);  h2 += h1
h3 ^= h2;  h2 = rotl(h2, 32);  h3 += h2
h0 ^= h3;  h3 = rotl(h3, 25);  h0 += h3
h1 ^= h0;  h0 = rotl(h0, 63);  h1 += h0
```

## Properties

### Avalanche Effect
SpookyHash achieves excellent avalanche:
- Every input bit affects every output bit
- One bit change → ~50% of output bits change

### Speed Characteristics
| Message Size | Throughput |
|--------------|------------|
| < 32 bytes | ~2 GB/s |
| 32-192 bytes | ~4 GB/s |
| > 192 bytes | ~8-10 GB/s |

### Version 2 vs Version 1
Version 1 had a flaw where certain bit patterns could produce the same hash. Version 2 fixes this by ensuring the message length is mixed into the final block differently.

## Use Cases

### Ideal For
- Large file checksums
- Data deduplication
- Content-addressable storage
- Database indexing
- Bloom filters with large keys

### Not Ideal For
- Very short keys (< 16 bytes) - MurmurHash is faster
- Security-sensitive applications - use SipHash
- Hash tables with untrusted input - use SipHash

## Streaming Implementation Notes

### Buffer Size
The streaming implementation uses a 96-byte internal buffer to accumulate partial blocks. For short messages, the entire message may be buffered before the short-message path is used.

### Short vs Long Detection
In streaming mode, we don't know the total length until finalization. The implementation:
1. Always initializes for long messages
2. At finalization, checks if total < 192 bytes
3. If short, runs the short algorithm on buffered data
4. If long, finalizes the long algorithm state

### Memory Usage
- Internal buffer: 192 bytes (ArrayPool)
- State: 96 bytes (12 × 8 bytes)
- Total: ~300 bytes per hasher instance

## Comparison with Other Hash Functions

| Property | SpookyHash | MurmurHash3 | xxHash |
|----------|------------|-------------|--------|
| Output Size | 128 bits | 128 bits | 64/128 bits |
| Speed (long) | ~10 GB/s | ~6 GB/s | ~13 GB/s |
| Speed (short) | ~2 GB/s | ~3 GB/s | ~4 GB/s |
| State Size | 96 bytes | 16 bytes | 32 bytes |
| Block Size | 96 bytes | 16 bytes | 32 bytes |

## References

1. [SpookyHash Official Page](http://burtleburtle.net/bob/hash/spooky.html)
2. [SpookyHash V2 Source Code](http://burtleburtle.net/bob/c/SpookyV2.cpp)
3. [Bob Jenkins' Hash Functions](http://burtleburtle.net/bob/hash/index.html)
4. [GitHub - SpookyHash](https://github.com/centaurean/spookyhash)
