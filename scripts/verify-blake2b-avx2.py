#!/usr/bin/env python3
"""Verify and generate BLAKE2b AVX2 message loading operations.

Simulates all AVX2 intrinsics to validate that each round's message vectors
contain the correct words according to the BLAKE2b sigma schedule.
"""

# BLAKE2b sigma schedule (12 rounds x 16 entries)
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],  # repeat round 0
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],  # repeat round 1
]

# Message words as source vectors
# msg0=[w0,w1,w2,w3], msg1=[w4,w5,w6,w7], msg2=[w8,w9,w10,w11], msg3=[w12,w13,w14,w15]
MSG = [[0,1,2,3], [4,5,6,7], [8,9,10,11], [12,13,14,15]]

def unpack_low(a, b):
    """AVX2 UnpackLow for 64-bit: per 128-bit lane, interleave low elements"""
    return [a[0], b[0], a[2], b[2]]

def unpack_high(a, b):
    """AVX2 UnpackHigh for 64-bit: per 128-bit lane, interleave high elements"""
    return [a[1], b[1], a[3], b[3]]

def permute4x64(v, imm):
    """AVX2 Permute4x64: output[i] = v[(imm >> (i*2)) & 3]"""
    return [v[(imm >> (i*2)) & 3] for i in range(4)]

def permute2x128(a, b, imm):
    """AVX2 Permute2x128: select 128-bit lanes"""
    lanes = [a[:2], a[2:], b[:2], b[2:]]
    lo_sel = imm & 3
    hi_sel = (imm >> 4) & 3
    return lanes[lo_sel] + lanes[hi_sel]

def blend32(a, b, mask):
    """AVX2 Blend at 32-bit granularity, but we work with 64-bit elements.
    Each 64-bit element i is controlled by bits 2*i and 2*i+1."""
    result = list(a)
    for i in range(4):
        lo_bit = (mask >> (2*i)) & 1
        hi_bit = (mask >> (2*i+1)) & 1
        if lo_bit and hi_bit:
            result[i] = b[i]
        elif lo_bit or hi_bit:
            # Partial blend - not typically used for 64-bit elements
            result[i] = f"PARTIAL({a[i]},{b[i]})"
    return result

def get_expected(rnd, phase, vec):
    """Get expected message words for a given round, phase (col/diag), and vector (b0/b1).

    For column phase: b0=[sigma[0],sigma[2],sigma[4],sigma[6]], b1=[sigma[1],sigma[3],sigma[5],sigma[7]]
    For diagonal phase: b0=[sigma[8],sigma[10],sigma[12],sigma[14]], b1=[sigma[9],sigma[11],sigma[13],sigma[15]]
    """
    s = SIGMA[rnd]
    base = 0 if phase == 'col' else 8
    if vec == 'b0':
        return [s[base+0], s[base+2], s[base+4], s[base+6]]
    else:
        return [s[base+1], s[base+3], s[base+5], s[base+7]]

# Define message source vectors
msg0 = [0,1,2,3]
msg1 = [4,5,6,7]
msg2 = [8,9,10,11]
msg3 = [12,13,14,15]

def verify_round(rnd, col_b0_ops, col_b1_ops, diag_b0_ops, diag_b1_ops):
    """Verify that the constructed vectors match the expected sigma schedule."""
    expected_col_b0 = get_expected(rnd, 'col', 'b0')
    expected_col_b1 = get_expected(rnd, 'col', 'b1')
    expected_diag_b0 = get_expected(rnd, 'diag', 'b0')
    expected_diag_b1 = get_expected(rnd, 'diag', 'b1')

    results = {
        'col_b0': (col_b0_ops, expected_col_b0),
        'col_b1': (col_b1_ops, expected_col_b1),
        'diag_b0': (diag_b0_ops, expected_diag_b0),
        'diag_b1': (diag_b1_ops, expected_diag_b1),
    }

    all_ok = True
    for name, (actual, expected) in results.items():
        if actual != expected:
            print(f"  FAIL Round {rnd} {name}: got {actual}, expected {expected}")
            all_ok = False

    if all_ok:
        print(f"  OK Round {rnd}")
    return all_ok


print("=== Verifying BLAKE2b AVX2 message loading ===\n")

all_ok = True

# Round 0
r0_col_b0 = permute4x64(unpack_low(msg0, msg1), 0xD8)
r0_col_b1 = permute4x64(unpack_high(msg0, msg1), 0xD8)
r0_diag_b0 = permute4x64(unpack_low(msg2, msg3), 0xD8)
r0_diag_b1 = permute4x64(unpack_high(msg2, msg3), 0xD8)
all_ok &= verify_round(0, r0_col_b0, r0_col_b1, r0_diag_b0, r0_diag_b1)

# Round 1
t0 = blend32(msg3, msg1, 0x03)
t1 = unpack_high(msg2, msg3)
r1_col_b0 = permute2x128(permute4x64(t0, 0x06), t1, 0x20)
t0 = blend32(msg3, msg1, 0x30)
r1_col_b1 = permute2x128(permute4x64(msg2, 0x02), permute4x64(t0, 0x0B), 0x20)

t0 = blend32(msg2, msg1, 0x0C)
r1_diag_b0 = permute2x128(permute4x64(msg0, 0x01), permute4x64(t0, 0x0D), 0x20)
t0 = blend32(msg3, msg0, 0x30)
r1_diag_b1 = permute2x128(permute4x64(t0, 0x02), unpack_high(msg1, msg0), 0x31)
all_ok &= verify_round(1, r1_col_b0, r1_col_b1, r1_diag_b0, r1_diag_b1)

# Round 2
t0 = blend32(msg2, msg3, 0x03)
t1 = permute4x64(unpack_high(msg1, msg3), 0x03)
r2_col_b0 = permute2x128(permute4x64(t0, 0x0C), t1, 0x20)
t0 = blend32(msg0, msg3, 0x0C)
r2_col_b1 = permute2x128(unpack_low(msg2, msg0), permute4x64(t0, 0x09), 0x20)

t0 = blend32(msg2, msg0, 0xC0)
t1 = blend32(msg1, msg2, 0x0C)
r2_diag_b0 = permute2x128(permute4x64(t0, 0x0B), permute4x64(t1, 0x0D), 0x20)
t0 = permute4x64(unpack_low(msg3, msg1), 0x0B)
t1 = blend32(msg0, msg1, 0x03)
r2_diag_b1 = permute2x128(t0, permute4x64(t1, 0x01), 0x20)
all_ok &= verify_round(2, r2_col_b0, r2_col_b1, r2_diag_b0, r2_diag_b1)

# Round 3
t0 = permute4x64(unpack_high(msg1, msg0), 0x0B)
t1 = blend32(msg3, msg2, 0xC0)
r3_col_b0 = permute2x128(t0, permute4x64(t1, 0x07), 0x20)
r3_col_b1 = permute2x128(unpack_high(msg2, msg0), permute4x64(msg3, 0x08), 0x20)

t0 = blend32(msg0, msg1, 0x0C)
t1 = blend32(msg1, msg3, 0xC0)
r3_diag_b0 = permute2x128(permute4x64(t0, 0x09), permute4x64(t1, 0x0C), 0x20)
t0 = permute4x64(unpack_low(msg1, msg2), 0x0B)
r3_diag_b1 = permute2x128(t0, unpack_low(msg0, msg2), 0x20)
all_ok &= verify_round(3, r3_col_b0, r3_col_b1, r3_diag_b0, r3_diag_b1)

# Round 4
r4_col_b0 = permute2x128(unpack_high(msg2, msg1), unpack_low(msg0, msg2), 0x30)
t0 = blend32(msg0, msg1, 0xC0)
t1 = blend32(msg1, msg3, 0xC0)
r4_col_b1 = permute2x128(permute4x64(t0, 0x0C), permute4x64(t1, 0x0C), 0x20)

t0 = blend32(msg3, msg2, 0xC0)
t1 = blend32(msg1, msg0, 0xC0)
r4_diag_b0 = permute2x128(permute4x64(t0, 0x0B), permute4x64(t1, 0x0B), 0x20)
t0 = blend32(msg0, msg3, 0x03)
r4_diag_b1 = permute2x128(permute4x64(t0, 0x04), blend32(msg2, msg3, 0x0C), 0x20)
all_ok &= verify_round(4, r4_col_b0, r4_col_b1, r4_diag_b0, r4_diag_b1)

# Round 5
t0 = permute4x64(unpack_low(msg0, msg1), 0x0B)
r5_col_b0 = permute2x128(t0, unpack_low(msg0, msg2), 0x20)
t0 = blend32(msg3, msg2, 0x30)
r5_col_b1 = permute2x128(permute4x64(t0, 0x08), unpack_high(msg2, msg0), 0x31)

t0 = blend32(msg3, msg0, 0x0C)
r5_diag_b0 = permute2x128(permute4x64(msg1, 0x0C), permute4x64(t0, 0x0D), 0x20)
t0 = blend32(msg3, msg2, 0x0C)
r5_diag_b1 = permute2x128(unpack_high(msg3, msg1), permute4x64(t0, 0x09), 0x20)
all_ok &= verify_round(5, r5_col_b0, r5_col_b1, r5_diag_b0, r5_diag_b1)

# Round 6
t0 = blend32(msg3, msg0, 0x0C)
t1 = blend32(msg3, msg1, 0x03)
r6_col_b0 = permute2x128(t0, permute4x64(t1, 0x08), 0x20)
t0 = permute4x64(unpack_high(msg1, msg3), 0x03)
t1 = blend32(msg3, msg2, 0x30)
r6_col_b1 = permute2x128(t0, permute4x64(t1, 0x06), 0x20)

t0 = blend32(msg0, msg1, 0x30)
r6_diag_b0 = permute2x128(permute4x64(t0, 0x08), permute4x64(msg2, 0x04), 0x20)
t0 = permute4x64(unpack_high(msg1, msg0), 0x0B)
t1 = blend32(msg0, msg2, 0xC0)
r6_diag_b1 = permute2x128(t0, permute4x64(t1, 0x0B), 0x20)
all_ok &= verify_round(6, r6_col_b0, r6_col_b1, r6_diag_b0, r6_diag_b1)

# Round 7
t0 = blend32(msg3, msg1, 0xC0)
t1 = blend32(msg3, msg0, 0xC0)
r7_col_b0 = permute2x128(permute4x64(t0, 0x07), permute4x64(t1, 0x0C), 0x20)
t0 = blend32(msg2, msg3, 0x30)
r7_col_b1 = permute2x128(permute4x64(t0, 0x0E), unpack_high(msg0, msg2), 0x20)

t0 = permute4x64(unpack_high(msg1, msg3), 0x03)
t1 = blend32(msg2, msg0, 0x30)
r7_diag_b0 = permute2x128(t0, permute4x64(t1, 0x08), 0x20)
r7_diag_b1 = permute2x128(unpack_low(msg0, msg1), unpack_low(msg1, msg2), 0x30)
all_ok &= verify_round(7, r7_col_b0, r7_col_b1, r7_diag_b0, r7_diag_b1)

# Round 8
t0 = permute4x64(unpack_low(msg1, msg3), 0x0B)
t1 = blend32(msg2, msg0, 0x03)
r8_col_b0 = permute2x128(t0, permute4x64(t1, 0x0C), 0x20)
t0 = blend32(msg3, msg2, 0x0C)
t1 = blend32(msg0, msg2, 0x03)
r8_col_b1 = permute2x128(permute4x64(t0, 0x0D), permute4x64(t1, 0x0C), 0x20)

t0 = blend32(msg0, msg2, 0x30)
r8_diag_b0 = permute2x128(msg3, permute4x64(t0, 0x06), 0x20)
t0 = blend32(msg0, msg1, 0xC0)
r8_diag_b1 = permute2x128(permute4x64(t0, 0x0B), msg1, 0x20)
all_ok &= verify_round(8, r8_col_b0, r8_col_b1, r8_diag_b0, r8_diag_b1)

# Round 9
t0 = blend32(msg1, msg0, 0x0C)
r9_col_b0 = permute2x128(permute4x64(msg2, 0x02), permute4x64(t0, 0x0D), 0x20)
t0 = blend32(msg0, msg1, 0x03)
r9_col_b1 = permute2x128(permute4x64(t0, 0x08), permute4x64(msg1, 0x09), 0x20)

t0 = blend32(msg3, msg2, 0x0C)
t1 = blend32(msg0, msg3, 0x03)
r9_diag_b0 = permute2x128(permute4x64(t0, 0x0D), permute4x64(t1, 0x0C), 0x20)
t0 = blend32(msg2, msg3, 0x30)
t1 = blend32(msg3, msg0, 0x03)
r9_diag_b1 = permute2x128(permute4x64(t0, 0x0E), permute4x64(t1, 0x04), 0x20)
all_ok &= verify_round(9, r9_col_b0, r9_col_b1, r9_diag_b0, r9_diag_b1)

# Rounds 10 and 11 (repeat of rounds 0 and 1)
all_ok &= verify_round(10, r0_col_b0, r0_col_b1, r0_diag_b0, r0_diag_b1)
all_ok &= verify_round(11, r1_col_b0, r1_col_b1, r1_diag_b0, r1_diag_b1)

print()
if all_ok:
    print("ALL ROUNDS VERIFIED CORRECT!")
else:
    print("ERRORS FOUND - fix the failing rounds")
