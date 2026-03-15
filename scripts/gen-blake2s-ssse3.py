#!/usr/bin/env python3
"""
BLAKE2s SSSE3 Message Loading Code Generator

Generates optimized SSE instruction sequences to construct per-round message
vectors from 4 source vectors (msg0-msg3), replacing scalar loads + Vector128.Create
(which generate expensive GPR->SIMD pinsrd instructions) with vector loads + shuffles.

Source vectors (loaded from 64-byte block):
  msg0 = [m0, m1, m2, m3]     (bytes 0-15)
  msg1 = [m4, m5, m6, m7]     (bytes 16-31)
  msg2 = [m8, m9, m10, m11]   (bytes 32-47)
  msg3 = [m12, m13, m14, m15] (bytes 48-63)

SSE operations used (SSE2 + SSSE3 only, no SSE4.1 required):
  pshufd(src, imm)     - permute 4 uint32 lanes within one vector
  shufps(a, b, imm)    - pick 2 from a (lanes 0,1) + 2 from b (lanes 2,3)
  punpckldq(a, b)      - interleave lower halves: [a0,b0,a1,b1]
  punpckhdq(a, b)      - interleave upper halves: [a2,b2,a3,b3]
"""

import sys

# BLAKE2s sigma schedule
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
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 13, 12, 0],
]

MSG = {
    0: [0, 1, 2, 3],
    1: [4, 5, 6, 7],
    2: [8, 9, 10, 11],
    3: [12, 13, 14, 15],
}


def sim_pshufd(src, imm):
    return [src[(imm >> (i * 2)) & 3] for i in range(4)]

def sim_shufps(a, b, imm):
    return [a[(imm >> 0) & 3], a[(imm >> 2) & 3], b[(imm >> 4) & 3], b[(imm >> 6) & 3]]

def sim_unpacklo(a, b):
    return [a[0], b[0], a[1], b[1]]

def sim_unpackhi(a, b):
    return [a[2], b[2], a[3], b[3]]

def make_imm(l0, l1, l2, l3):
    return l0 | (l1 << 2) | (l2 << 4) | (l3 << 6)


def find_best_sequence(target):
    """Find optimal instruction sequence for target using simulation-based search."""
    srcs = [t // 4 for t in target]
    lanes = [t % 4 for t in target]
    unique_srcs = set(srcs)

    # ---- 1 instruction: pshufd ----
    if len(unique_srcs) == 1:
        s = srcs[0]
        if lanes == [0, 1, 2, 3]:
            return 0, ("identity", s)
        return 1, ("pshufd", s, make_imm(*lanes))

    # ---- 1 instruction: shufps (lower 2 from A, upper 2 from B) ----
    if srcs[0] == srcs[1] and srcs[2] == srcs[3] and srcs[0] != srcs[2]:
        return 1, ("shufps", srcs[0], srcs[2], make_imm(*lanes))

    # ---- 2 instructions ----
    best_2 = None

    # Strategy A: shufps(a,b) -> tmp, pshufd(tmp) -> result
    # Works when all target elements come from exactly 2 sources
    if len(unique_srcs) == 2:
        for sa in range(4):
            for sb in range(4):
                if sa == sb:
                    continue
                src_a, src_b = MSG[sa], MSG[sb]
                # Try all imm1: need all 4 target elements present in tmp
                for imm1 in range(256):
                    tmp = sim_shufps(src_a, src_b, imm1)
                    if all(t in tmp for t in target):
                        idx = [tmp.index(t) for t in target]
                        imm2 = make_imm(*idx)
                        if sim_pshufd(tmp, imm2) == target:
                            best_2 = ("shufps_pshufd", sa, sb, imm1, imm2)
                            break
                if best_2:
                    break
            if best_2:
                break

    # Strategy B: unpacklo/hi(a,b) -> tmp, pshufd(tmp) -> result
    if not best_2:
        for sa in range(4):
            for sb in range(4):
                if sa == sb:
                    continue
                for fn, fn_name in [(sim_unpacklo, "lo"), (sim_unpackhi, "hi")]:
                    tmp = fn(MSG[sa], MSG[sb])
                    if all(t in tmp for t in target):
                        idx = [tmp.index(t) for t in target]
                        imm2 = make_imm(*idx)
                        if sim_pshufd(tmp, imm2) == target:
                            best_2 = ("unpack_pshufd", fn_name, sa, sb, imm2)
                            break
                if best_2:
                    break
            if best_2:
                break

    # Strategy C: shufps(a,b) -> tmp, shufps(tmp, c) or shufps(c, tmp) -> result
    # For 3+ source targets. Use targeted search based on constraints.
    if not best_2:
        # Form 1: shufps(tmp, c, imm2) -> result
        # result[0,1] from tmp, result[2,3] from c
        # t2,t3 must share a source
        if srcs[2] == srcs[3]:
            c = srcs[2]
            best_2 = _search_shufps_shufps_tc(target, srcs, lanes, c)

        # Form 2: shufps(c, tmp, imm2) -> result
        # result[0,1] from c, result[2,3] from tmp
        # t0,t1 must share a source
        if not best_2 and srcs[0] == srcs[1]:
            c = srcs[0]
            best_2 = _search_shufps_shufps_ct(target, srcs, lanes, c)

    if best_2:
        return 2, best_2

    # ---- 3 instruction fallback (always works) ----
    return 3, _fallback_3(target, srcs, lanes)


def _search_shufps_shufps_tc(target, srcs, lanes, c):
    """Search for shufps(a,b)->tmp, shufps(tmp,c)->result where result[2,3] from c."""
    # result = shufps(tmp, msg_c, imm2)
    # result[0] = tmp[i0], result[1] = tmp[i1], result[2] = msg_c[l2], result[3] = msg_c[l3]
    # tmp = shufps(msg_a, msg_b, imm1)
    # tmp[0] = msg_a[j0], tmp[1] = msg_a[j1], tmp[2] = msg_b[j2], tmp[3] = msg_b[j3]

    # For t0: need to find it in tmp at some lane i0
    # For t1: need to find it in tmp at some lane i1
    # Then the sources (a or b) of those tmp lanes must match

    t0_src, t0_lane = srcs[0], lanes[0]
    t1_src, t1_lane = srcs[1], lanes[1]

    # Try all possible ways t0 and t1 map to tmp lanes
    for i0 in range(4):
        for i1 in range(4):
            if i0 == i1:
                continue
            # Determine which source (a or b) provides t0 and t1
            # tmp lanes 0,1 come from a; lanes 2,3 come from b
            a_src = None
            b_src = None
            imm1_bits = [0, 0, 0, 0]

            # t0 -> tmp[i0]
            if i0 < 2:
                a_src = t0_src
                imm1_bits[i0] = t0_lane
            else:
                b_src = t0_src
                imm1_bits[i0] = t0_lane

            # t1 -> tmp[i1]
            if i1 < 2:
                if a_src is not None and a_src != t1_src:
                    continue  # conflict
                a_src = t1_src
                imm1_bits[i1] = t1_lane
            else:
                if b_src is not None and b_src != t1_src:
                    continue
                b_src = t1_src
                imm1_bits[i1] = t1_lane

            if a_src is None:
                a_src = 0  # don't care
            if b_src is None:
                b_src = 0  # don't care

            imm1 = make_imm(*imm1_bits)
            imm2 = make_imm(i0, i1, lanes[2], lanes[3])

            tmp = sim_shufps(MSG[a_src], MSG[b_src], imm1)
            result = sim_shufps(tmp, MSG[c], imm2)
            if result == target:
                return ("shufps_shufps_tc", a_src, b_src, imm1, c, imm2)

    return None


def _search_shufps_shufps_ct(target, srcs, lanes, c):
    """Search for shufps(a,b)->tmp, shufps(c,tmp)->result where result[0,1] from c."""
    t2_src, t2_lane = srcs[2], lanes[2]
    t3_src, t3_lane = srcs[3], lanes[3]

    for i2 in range(4):
        for i3 in range(4):
            if i2 == i3:
                continue
            a_src = None
            b_src = None
            imm1_bits = [0, 0, 0, 0]

            if i2 < 2:
                a_src = t2_src
                imm1_bits[i2] = t2_lane
            else:
                b_src = t2_src
                imm1_bits[i2] = t2_lane

            if i3 < 2:
                if a_src is not None and a_src != t3_src:
                    continue
                a_src = t3_src
                imm1_bits[i3] = t3_lane
            else:
                if b_src is not None and b_src != t3_src:
                    continue
                b_src = t3_src
                imm1_bits[i3] = t3_lane

            if a_src is None:
                a_src = 0
            if b_src is None:
                b_src = 0

            imm1 = make_imm(*imm1_bits)
            imm2 = make_imm(lanes[0], lanes[1], i2, i3)

            tmp = sim_shufps(MSG[a_src], MSG[b_src], imm1)
            result = sim_shufps(MSG[c], tmp, imm2)
            if result == target:
                return ("shufps_shufps_ct", a_src, b_src, imm1, c, imm2)

    return None


def _fallback_3(target, srcs, lanes):
    """Guaranteed 3-instruction solution for any target.

    temp_lo = shufps(src_t0, src_t1) with t0 at [0] and t1 at [2]
    temp_hi = shufps(src_t2, src_t3) with t2 at [0] and t3 at [2]
    result  = shufps(temp_lo, temp_hi, 0x88) = [lo[0], lo[2], hi[0], hi[2]]
    """
    s0, l0 = srcs[0], lanes[0]
    s1, l1 = srcs[1], lanes[1]
    s2, l2 = srcs[2], lanes[2]
    s3, l3 = srcs[3], lanes[3]

    imm_lo = make_imm(l0, l0, l1, l1)
    imm_hi = make_imm(l2, l2, l3, l3)

    return ("fallback3", s0, s1, l0, l1, imm_lo, s2, s3, l2, l3, imm_hi)


def verify(seq, target):
    """Verify sequence by simulation."""
    kind = seq[0]
    if kind == "identity":
        result = list(MSG[seq[1]])
    elif kind == "pshufd":
        result = sim_pshufd(MSG[seq[1]], seq[2])
    elif kind == "shufps":
        result = sim_shufps(MSG[seq[1]], MSG[seq[2]], seq[3])
    elif kind == "shufps_pshufd":
        tmp = sim_shufps(MSG[seq[1]], MSG[seq[2]], seq[3])
        result = sim_pshufd(tmp, seq[4])
    elif kind == "shufps_shufps_tc":
        tmp = sim_shufps(MSG[seq[1]], MSG[seq[2]], seq[3])
        result = sim_shufps(tmp, MSG[seq[4]], seq[5])
    elif kind == "shufps_shufps_ct":
        tmp = sim_shufps(MSG[seq[1]], MSG[seq[2]], seq[3])
        result = sim_shufps(MSG[seq[4]], tmp, seq[5])
    elif kind == "unpack_pshufd":
        fn = sim_unpacklo if seq[1] == "lo" else sim_unpackhi
        tmp = fn(MSG[seq[2]], MSG[seq[3]])
        result = sim_pshufd(tmp, seq[4])
    elif kind == "fallback3":
        s0, s1, l0, l1, imm_lo, s2, s3, l2, l3, imm_hi = seq[1:]
        if s0 == s1:
            tmp_lo = sim_pshufd(MSG[s0], make_imm(l0, 0, l1, 0))
        else:
            tmp_lo = sim_shufps(MSG[s0], MSG[s1], imm_lo)
        if s2 == s3:
            tmp_hi = sim_pshufd(MSG[s2], make_imm(l2, 0, l3, 0))
        else:
            tmp_hi = sim_shufps(MSG[s2], MSG[s3], imm_hi)
        result = sim_shufps(tmp_lo, tmp_hi, 0x88)
    else:
        raise ValueError(f"Unknown kind: {kind}")

    return result == target


def gen_csharp(seq, var_name):
    """Generate C# code lines for the instruction sequence."""
    kind = seq[0]

    if kind == "identity":
        return [f"{var_name} = msg{seq[1]};"]
    if kind == "pshufd":
        return [f"{var_name} = Sse2.Shuffle(msg{seq[1]}.AsInt32(), 0x{seq[2]:02x}).AsUInt32();"]
    if kind == "shufps":
        return [f"{var_name} = Sse.Shuffle(msg{seq[1]}.AsSingle(), msg{seq[2]}.AsSingle(), 0x{seq[3]:02x}).AsUInt32();"]
    if kind == "shufps_pshufd":
        sa, sb, imm1, imm2 = seq[1], seq[2], seq[3], seq[4]
        return [
            f"tt = Sse.Shuffle(msg{sa}.AsSingle(), msg{sb}.AsSingle(), 0x{imm1:02x}).AsUInt32();",
            f"{var_name} = Sse2.Shuffle(tt.AsInt32(), 0x{imm2:02x}).AsUInt32();",
        ]
    if kind == "shufps_shufps_tc":
        sa, sb, imm1, sc, imm2 = seq[1], seq[2], seq[3], seq[4], seq[5]
        return [
            f"tt = Sse.Shuffle(msg{sa}.AsSingle(), msg{sb}.AsSingle(), 0x{imm1:02x}).AsUInt32();",
            f"{var_name} = Sse.Shuffle(tt.AsSingle(), msg{sc}.AsSingle(), 0x{imm2:02x}).AsUInt32();",
        ]
    if kind == "shufps_shufps_ct":
        sa, sb, imm1, sc, imm2 = seq[1], seq[2], seq[3], seq[4], seq[5]
        return [
            f"tt = Sse.Shuffle(msg{sa}.AsSingle(), msg{sb}.AsSingle(), 0x{imm1:02x}).AsUInt32();",
            f"{var_name} = Sse.Shuffle(msg{sc}.AsSingle(), tt.AsSingle(), 0x{imm2:02x}).AsUInt32();",
        ]
    if kind == "unpack_pshufd":
        fn_name, sa, sb, imm2 = seq[1], seq[2], seq[3], seq[4]
        fn = "UnpackLow" if fn_name == "lo" else "UnpackHigh"
        return [
            f"tt = Sse2.{fn}(msg{sa}.AsInt32(), msg{sb}.AsInt32()).AsUInt32();",
            f"{var_name} = Sse2.Shuffle(tt.AsInt32(), 0x{imm2:02x}).AsUInt32();",
        ]
    if kind == "fallback3":
        s0, s1, l0, l1, imm_lo, s2, s3, l2, l3, imm_hi = seq[1:]
        lines = []
        if s0 == s1:
            imm = make_imm(l0, 0, l1, 0)
            lines.append(f"tt = Sse2.Shuffle(msg{s0}.AsInt32(), 0x{imm:02x}).AsUInt32();")
        else:
            lines.append(f"tt = Sse.Shuffle(msg{s0}.AsSingle(), msg{s1}.AsSingle(), 0x{imm_lo:02x}).AsUInt32();")
        if s2 == s3:
            imm = make_imm(l2, 0, l3, 0)
            lines.append(f"tu = Sse2.Shuffle(msg{s2}.AsInt32(), 0x{imm:02x}).AsUInt32();")
        else:
            lines.append(f"tu = Sse.Shuffle(msg{s2}.AsSingle(), msg{s3}.AsSingle(), 0x{imm_hi:02x}).AsUInt32();")
        lines.append(f"{var_name} = Sse.Shuffle(tt.AsSingle(), tu.AsSingle(), 0x88).AsUInt32();")
        return lines

    raise ValueError(f"Unknown kind: {kind}")


def main():
    print("=" * 70)
    print("BLAKE2s SSSE3 Message Loading Code Generator")
    print("=" * 70)

    total_instr = 0
    all_round_code = []
    all_ok = True

    for r in range(10):
        s = SIGMA[r]
        phases = [
            ("Column", [s[0], s[2], s[4], s[6]], [s[1], s[3], s[5], s[7]]),
            ("Diagonal", [s[8], s[10], s[12], s[14]], [s[9], s[11], s[13], s[15]]),
        ]
        print(f"\n--- Round {r} ---")
        round_code = []

        for phase_name, b0_t, b1_t in phases:
            n0, seq_b0 = find_best_sequence(b0_t)
            n1, seq_b1 = find_best_sequence(b1_t)
            v0 = verify(seq_b0, b0_t)
            v1 = verify(seq_b1, b1_t)
            all_ok = all_ok and v0 and v1
            total_instr += n0 + n1

            desc0 = f"[m{b0_t[0]}, m{b0_t[1]}, m{b0_t[2]}, m{b0_t[3]}]"
            desc1 = f"[m{b1_t[0]}, m{b1_t[1]}, m{b1_t[2]}, m{b1_t[3]}]"
            print(f"  {phase_name}: b0={desc0} -> {seq_b0[0]} ({n0} instr) {'OK' if v0 else 'FAIL'}")
            print(f"            b1={desc1} -> {seq_b1[0]} ({n1} instr) {'OK' if v1 else 'FAIL'}")

            round_code.append((r, phase_name, gen_csharp(seq_b0, "b0"), gen_csharp(seq_b1, "b1")))
        all_round_code.append(round_code)

    print(f"\n{'=' * 70}")
    print(f"Total message loading instructions: {total_instr}")
    print(f"All verified: {all_ok}")

    if not all_ok:
        print("ERROR: Verification failed!", file=sys.stderr)
        return 1

    # Output C# code
    print("\n// ---- Generated C# Code for CompressSsse3 message loading ----\n")
    print("// Load message block as 4 vector registers (replaces 16 scalar reads)")
    print("ref byte blockRef = ref MemoryMarshal.GetReference(block);")
    print("var msg0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref blockRef);")
    print("var msg1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref blockRef, 16));")
    print("var msg2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref blockRef, 32));")
    print("var msg3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref blockRef, 48));")

    mixing_col = """\t\trow0 = Sse2.Add(Sse2.Add(row0, row1), b0);
\t\trow3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
\t\trow2 = Sse2.Add(row2, row3);
\t\tt0 = Sse2.Xor(row1, row2);
\t\trow1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
\t\trow0 = Sse2.Add(Sse2.Add(row0, row1), b1);
\t\trow3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
\t\trow2 = Sse2.Add(row2, row3);
\t\tt0 = Sse2.Xor(row1, row2);
\t\trow1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
\t\t// Diagonalize
\t\trow1 = Sse2.Shuffle(row1.AsInt32(), 0x39).AsUInt32();
\t\trow2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
\t\trow3 = Sse2.Shuffle(row3.AsInt32(), 0x93).AsUInt32();"""

    mixing_diag = """\t\trow0 = Sse2.Add(Sse2.Add(row0, row1), b0);
\t\trow3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt32();
\t\trow2 = Sse2.Add(row2, row3);
\t\tt0 = Sse2.Xor(row1, row2);
\t\trow1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 12), Sse2.ShiftLeftLogical(t0, 20));
\t\trow0 = Sse2.Add(Sse2.Add(row0, row1), b1);
\t\trow3 = Ssse3.Shuffle(Sse2.Xor(row3, row0).AsByte(), rot8Mask).AsUInt32();
\t\trow2 = Sse2.Add(row2, row3);
\t\tt0 = Sse2.Xor(row1, row2);
\t\trow1 = Sse2.Or(Sse2.ShiftRightLogical(t0, 7), Sse2.ShiftLeftLogical(t0, 25));
\t\t// Undiagonalize
\t\trow1 = Sse2.Shuffle(row1.AsInt32(), 0x93).AsUInt32();
\t\trow2 = Sse2.Shuffle(row2.AsInt32(), 0x4E).AsUInt32();
\t\trow3 = Sse2.Shuffle(row3.AsInt32(), 0x39).AsUInt32();"""

    for round_phases in all_round_code:
        for r, phase_name, code_b0, code_b1 in round_phases:
            if phase_name == "Column":
                print(f"\n\t\t// Round {r} - Column phase")
            else:
                print(f"\t\t// Round {r} - Diagonal phase")
            for line in code_b0:
                print(f"\t\t{line}")
            for line in code_b1:
                print(f"\t\t{line}")
            if phase_name == "Column":
                print(mixing_col)
            else:
                print(mixing_diag)

    print("\n// All 10 rounds verified correct by simulation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
