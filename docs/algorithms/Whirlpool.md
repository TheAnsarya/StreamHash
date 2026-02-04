# Whirlpool

## Overview

Whirlpool is a cryptographic hash function designed by Vincent Rijmen (co-designer of AES) and Paulo S. L. M. Barreto. It was adopted as ISO/IEC 10118-3:2004.

## Algorithm Characteristics

| Property | Value |
|----------|-------|
| **Output Size** | 512 bits (64 bytes) |
| **Block Size** | 512 bits (64 bytes) |
| **State Size** | 512 bits (8×8 byte matrix) |
| **Rounds** | 10 |
| **Structure** | Miyaguchi-Preneel with AES-like cipher |

## Design Features

- **Dedicated S-box**: Uses its own 8×8 S-box (not AES S-box)
- **MDS Matrix**: Circulant matrix [01, 01, 04, 01, 08, 05, 02, 09] for diffusion
- **GF(2^8)**: Uses polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
- **Miyaguchi-Preneel**: H(i+1) = E(K=H(i), M) XOR H(i) XOR M

## Performance

StreamHash provides a custom high-performance implementation with T-table optimization:

| Metric | BouncyCastle | StreamHash | Improvement |
|--------|--------------|------------|-------------|
| 1MB hash | ~58 ms | ~18 ms | **3.2x faster** |
| Memory | Higher GC | 696 bytes | Minimal allocation |

### Optimization Techniques

1. **T-table Optimization**: 8 tables of 256 × 64-bit entries combining SubBytes, ShiftColumns, and MixRows
2. **Efficient Round Function**: Unrolled loops for key expansion and state transformation
3. **Zero Hot-Path Allocations**: All temporary state is pre-allocated

## Usage

```csharp
using StreamHash.Core;

// One-shot API
byte[] hash = HashFacade.ComputeHash(data, HashAlgorithm.Whirlpool);
string hexHash = HashFacade.ComputeHashHex(data, HashAlgorithm.Whirlpool);

// Streaming API
using var whirlpool = HashFacade.CreateStreaming(HashAlgorithm.Whirlpool);
whirlpool.Update(chunk1);
whirlpool.Update(chunk2);
byte[] result = whirlpool.FinalizeBytes();
```

## Test Vectors

### Empty String
```
Input:  ""
Output: 19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7
        3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3
```

## References

- [Whirlpool Official Page](https://web.archive.org/web/20171129084214/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html)
- [ISO/IEC 10118-3:2004](https://www.iso.org/standard/39876.html)
- [NESSIE Project Report](https://www.cosic.esat.kuleuven.be/nessie/)
