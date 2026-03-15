# CRC-16

## Overview

CRC-16 (Cyclic Redundancy Check, 16-bit) is a family of error-detecting codes used in communication protocols and data storage. StreamHash implements multiple CRC-16 variants with pre-computed lookup tables.

## Variants

| Variant | Polynomial | Init | XOR Out | Reflect | Usage |
|---------|-----------|------|---------|---------|-------|
| **CRC-16/CCITT** | 0x1021 | 0xffff | 0x0000 | No | X.25, V.41 |
| **CRC-16/MODBUS** | 0x8005 | 0xffff | 0x0000 | Yes | Modbus RTU |
| **CRC-16/USB** | 0x8005 | 0xffff | 0xffff | Yes | USB tokens |
| **CRC-16/XMODEM** | 0x1021 | 0x0000 | 0x0000 | No | XMODEM protocol |
| **CRC-16/KERMIT** | 0x1021 | 0x0000 | 0x0000 | Yes | Kermit protocol |
| **CRC-16/DNP** | 0x3d65 | 0x0000 | 0xffff | Yes | DNP 3.0 |
| **CRC-16/MAXIM** | 0x8005 | 0x0000 | 0xffff | Yes | 1-Wire |

## Algorithm Design

### CRC Computation

CRC uses polynomial division in GF(2):

```
For each byte:
    If reflected: byte = reflect(byte)
    crc = table[(crc >> 8) ^ byte] ^ (crc << 8)
    (or for reflected: crc = table[(crc ^ byte) & 0xff] ^ (crc >> 8))
```

### Lookup Table

A 256-entry pre-computed table eliminates bit-by-bit processing:

```
table[i] = CRC of byte i (computed by shifting through the polynomial)
```

### Hardware Acceleration

Some CRC-16 variants can leverage PCLMULQDQ (carry-less multiplication) for hardware-accelerated computation.

## StreamHash Implementation

### Key Features

- **Multiple variants** — 7 CRC-16 flavors with different polynomials and parameters
- **Pre-computed lookup tables** — 256-entry tables for each variant
- **Single-byte streaming** — update CRC byte-by-byte
- **Configurable** — polynomial, init value, reflect, XOR output all parameterized

### Usage

```csharp
using StreamHash.Core;

var crc16 = HashFacade.Create(HashAlgorithmNames.Crc16Ccitt);
crc16.Update(data);
byte[] checksum = crc16.FinalizeHash();
```

## Security

**NOT a hash function.** CRC is an error-detection code, not a hash. It provides:

- Detection of common transmission errors (bit flips, burst errors)
- No resistance against intentional modification

## References

- [CRC Catalog — Greg Cook](https://reveng.sourceforge.io/crc-catalogue/16.htm)
- [A Painless Guide to CRC Error Detection Algorithms](https://zlib.net/crc_v3.txt)
