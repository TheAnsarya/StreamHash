# FNV-1a

## Overview

FNV (Fowler-Noll-Vo) is one of the simplest non-cryptographic hash functions. FNV-1a is the recommended variant that XORs the input byte before multiplying, providing slightly better avalanche than the original FNV-1.

## Variants

| Variant | Output | FNV Prime | Offset Basis |
|---------|--------|-----------|-------------|
| **FNV-1a-32** | 32 bits | 0x01000193 | 0x811c9dc5 |
| **FNV-1a-64** | 64 bits | 0x00000100000001b3 | 0xcbf29ce484222325 |

## Algorithm Design

### FNV-1a Core Loop

The algorithm is extraordinarily simple:

```
hash = offset_basis
for each byte in input:
    hash = hash XOR byte
    hash = hash * FNV_prime
return hash
```

### Properties

- **Byte-at-a-time processing** — no block structure
- **No buffering needed** — each byte updates the state immediately
- **Minimal state** — single hash word
- **Deterministic** — same input always produces same output

### FNV-1 vs FNV-1a

```
FNV-1:  hash = (hash * prime) XOR byte     ← multiply then XOR
FNV-1a: hash = (hash XOR byte) * prime     ← XOR then multiply (better avalanche)
```

## StreamHash Implementation

### Key Features

- **Single-byte streaming** — processes one byte at a time
- **Zero buffering** — no block buffer needed
- **Minimal allocations** — just the hash state variable
- **32-bit and 64-bit variants**

### Usage

```csharp
using StreamHash.Core;

var fnv32 = HashFacade.Create(HashAlgorithmNames.Fnv1a32);
fnv32.Update(data);
byte[] hash = fnv32.FinalizeHash();
```

## Performance

FNV-1a is not the fastest hash function for bulk data (it processes byte-by-byte), but it has very low overhead for small inputs, making it suitable for short string hashing and hash tables.

## Security

**NOT cryptographically secure.** FNV-1a is trivially invertible and provides no resistance against adversarial inputs.

Best used for:

- Hash tables (short strings)
- Simple checksums
- File identification

## References

- [FNV Hash — Fowler/Noll/Vo Hash](http://www.isthe.com/chongo/tech/comp/fnv/)
- [FNV Wikipedia Article](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function)
