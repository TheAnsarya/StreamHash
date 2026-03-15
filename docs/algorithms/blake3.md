# BLAKE3

## Overview

BLAKE3 is a cryptographic hash function designed by Jack O'Connell, Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O'Hearn. It builds on the BLAKE2 family with a Merkle tree structure for massive parallelism.

BLAKE3 is significantly faster than BLAKE2, SHA-256, and SHA-3 when hardware-accelerated, achieving multi-GB/s throughput with SIMD and multi-threading.

## Algorithm Details

| Property | Value |
|----------|-------|
| **Output Size** | 32 bytes (default, extendable) |
| **Block Size** | 64 bytes per block, 1024 bytes per chunk |
| **Word Size** | 32-bit |
| **Rounds** | 7 (reduced from BLAKE2s's 10) |
| **Security** | 128-bit |
| **Type** | XOF (extendable output function) |

## Algorithm Design

BLAKE3 uses a unique architecture combining:

1. **Merkle Tree Structure**: Input is divided into 1024-byte chunks, hashed into a binary tree
2. **Reduced Rounds**: Only 7 rounds of ChaCha-like compression (vs 10 for BLAKE2s)
3. **Domain Separation**: Flags distinguish chunk starts, chunk ends, parent nodes, and root finalization
4. **Keyed Mode**: Optional 256-bit key for MAC functionality

### Chunk Processing

Each 1024-byte chunk is processed as a sequence of 64-byte blocks:

1. First block initializes with chunk counter and `CHUNK_START` flag
2. Interior blocks update the chaining value
3. Last block adds `CHUNK_END` flag
4. Output is the chaining value for this chunk

### Merkle Tree

```
         root (ROOT flag)
        /              \
    parent           parent
   /      \         /      \
chunk0  chunk1  chunk2  chunk3
```

Parent nodes compress two 256-bit child chaining values into one.

## StreamHash Implementation

StreamHash implements BLAKE3 in pure safe C# without native interop.

### Key Characteristics

- **Pure C# implementation** — no Rust FFI, no unsafe code
- **7 rounds** of compression per block
- **Merkle tree** maintained via a stack of chaining values
- **Domain separation flags** for correct chunk/parent/root processing

### Usage

```csharp
using StreamHash.Core;

var hasher = HashFacade.Create(HashAlgorithmNames.Blake3);
hasher.Update(data);
byte[] hash = hasher.FinalizeHash();

// Streaming
using var blake3 = new NativeBlake3Digest();
blake3.Update(chunk1);
blake3.Update(chunk2);
byte[] result = blake3.FinalizeHash();
```

## Performance (1MB data)

| Implementation | Time | Notes |
|---|---:|---|
| Blake3 NuGet (Rust native, AVX2+SSE4) | 0.27 ms | Full SIMD + multi-lane |
| **StreamHash (pure safe C#)** | **2.16 ms** | No SIMD, single-threaded |

**Ratio: 8.08x** — The gap is expected because the reference implementation uses Rust with full AVX2/SSE4.1 SIMD acceleration and multi-lane chunk processing, while StreamHash is pure single-threaded C#.

### Why the Gap Exists

BLAKE3 is specifically designed for SIMD parallelism:

- The Merkle tree enables processing 4-8 chunks simultaneously with SIMD
- AVX2 processes 8 × 32-bit lanes in parallel
- The Rust `blake3` crate uses hand-tuned assembly for hot paths
- A pure scalar C# implementation cannot match this without SIMD intrinsics

## Security

- **Collision resistance**: 128-bit
- **Preimage resistance**: 256-bit
- **XOF**: Extendable output — can produce arbitrary-length digests
- **Keyed hashing**: Built-in MAC functionality
- **Key derivation**: Built-in KDF mode

## References

- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [BLAKE3 Official Implementation](https://github.com/BLAKE3-team/BLAKE3)
- [BLAKE3 Paper](https://github.com/BLAKE3-team/BLAKE3-specs)
