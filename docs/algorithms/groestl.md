# Grøstl

## Overview

Grøstl is a cryptographic hash function designed by Praveen Gauravaram, Lars R. Knudsen, Krystian Matusiewicz, Florian Mendel, Christian Rechberger, Martin Schläffer, and Søren S. Thomsen. It was a SHA-3 finalist and uses an AES-based design with two distinct permutations.

## Variants

| Variant | Output | State Size | Block Size | Rounds |
|---------|--------|-----------|-----------|--------|
| **Grøstl-256** | 256 bits (32 bytes) | 512 bits | 64 bytes | 10 |
| **Grøstl-512** | 512 bits (64 bytes) | 1024 bits | 128 bytes | 14 |

## Algorithm Design

### Wide-Pipe Construction

Grøstl uses the wide-pipe Merkle-Damgård variant with a final output transformation:

```
h_i = P(h_{i-1} ⊕ m_i) ⊕ Q(m_i) ⊕ h_{i-1}
output = Truncate(P(h_final) ⊕ h_final)
```

### Two Permutations (P and Q)

Both permutations use AES-like round transformations:

| Step | Description |
|------|-------------|
| **AddRoundConstant** | XOR with round-dependent constants (different for P vs Q) |
| **SubBytes** | AES S-box applied to every byte |
| **ShiftBytes** | Row shifting (different patterns for 512 vs 1024) |
| **MixBytes** | Column mixing using 8×8 MDS matrix in GF(2^8) |

### AES-NI Hardware Acceleration

Grøstl can leverage AES-NI instructions for the SubBytes and MixBytes steps, as it directly reuses the AES S-box.

### T-table Optimization

For platforms without AES-NI, Grøstl uses pre-computed T-tables (combining SubBytes + ShiftBytes + MixBytes into a single lookup).

## StreamHash Implementation

### Key Features

- **AES S-box based** — can potentially use AES-NI hardware acceleration
- **T-table implementation** — pre-computed 8 tables × 256 entries for combined transformation
- **10 rounds** (256-bit) or **14 rounds** (512-bit)
- **Configurable output size** — 256-bit and 512-bit variants

### Usage

```csharp
using StreamHash.Core;

var groestl256 = HashFacade.Create(HashAlgorithmNames.Groestl256);
groestl256.Update(data);
byte[] hash = groestl256.FinalizeHash();

var groestl512 = HashFacade.Create(HashAlgorithmNames.Groestl512);
```

## Security

- **SHA-3 finalist** — extensive cryptanalysis during the competition
- **AES-based security** — inherits security properties of the AES S-box
- **No known attacks** better than generic for full-round Grøstl
- **128-bit security** (Grøstl-256), **256-bit security** (Grøstl-512)

## References

- [Grøstl — A SHA-3 Candidate](https://www.groestl.info/)
- [Grøstl Specification (Version 2.0)](https://www.groestl.info/Groestl.pdf)
