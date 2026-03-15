# Tiger

## Overview

Tiger is a cryptographic hash function designed by Ross Anderson and Eli Biham in 1995. It was specifically designed for 64-bit platforms, making it one of the first hash functions to fully exploit 64-bit arithmetic.

## Algorithm Details

| Property | Value |
|----------|-------|
| **Output Size** | 192 bits (24 bytes) |
| **Block Size** | 64 bytes (512 bits) |
| **Word Size** | 64-bit |
| **Rounds** | 3 passes × 8 rounds = 24 total |
| **S-boxes** | 4 tables × 256 entries × 8 bytes = 8 KB |

## Algorithm Design

### State

Three 64-bit state words: `a`, `b`, `c` (192 bits total).

### Compression

Each 512-bit block is processed through 3 passes, each with 8 rounds:

```
Pass 1: multiply constant = 5
Pass 2: multiply constant = 7
Pass 3: multiply constant = 9
```

### Round Function

Each round uses S-box lookups from four 256-entry tables:

```
c ^= x[i]
a -= S1[c_byte0] ^ S2[c_byte2] ^ S3[c_byte4] ^ S4[c_byte6]
b += S4[c_byte1] ^ S3[c_byte3] ^ S2[c_byte5] ^ S1[c_byte7]
b *= mul
```

### Key Schedule

Between passes, the 8-word message block undergoes a key schedule transformation that combines XOR with subtraction and addition to maximize diffusion.

### 64-bit Optimization

Tiger's design is inherently 64-bit:

- All state words are `ulong` (64-bit)
- S-box outputs are 64-bit
- Multiplication by constants uses 64-bit multiply
- Little-endian byte order

## StreamHash Implementation

StreamHash implements Tiger natively with pre-computed S-box lookup tables.

### Key Features

- **4 S-boxes** with 256 entries each (8 KB total lookup data)
- **Little-endian** byte ordering
- **3-pass structure** with different multiplicative constants
- **Pure safe C#** — no unsafe code

### Usage

```csharp
using StreamHash.Core;

var hasher = HashFacade.Create(HashAlgorithmNames.Tiger192);
hasher.Update(data);
byte[] hash = hasher.FinalizeHash();
```

## Performance (1MB data)

| Implementation | Time | Ratio |
|---|---:|---:|
| **StreamHash** | **1.98 ms** | **0.89x** |
| BouncyCastle | 2.21 ms | 1.00x |

StreamHash is approximately **10% faster** than BouncyCastle.

## Security

- **192-bit output** — provides 96-bit collision resistance
- **No known practical attacks** on full Tiger
- **Used in** TTH (Tiger Tree Hash) for file sharing protocols
- **Not standardized** by NIST or ISO — less common in modern applications

## References

- [Tiger: A Fast New Hash Function (Paper)](https://www.cl.cam.ac.uk/~rja14/Papers/tiger.pdf)
- [Ross Anderson's Tiger Page](https://www.cl.cam.ac.uk/~rja14/tiger.html)
