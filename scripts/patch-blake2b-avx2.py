#!/usr/bin/env python3
"""Patch Blake2b.cs CompressAvx2 with verified-correct AVX2 message loading code.

Replaces the round bodies in CompressAvx2 with auto-generated, simulation-verified
permutation sequences for all 12 rounds of BLAKE2b.
"""
import re

# BLAKE2b sigma schedule
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
]

MSG_NAMES = ["msg0", "msg1", "msg2", "msg3"]

def src_vec(w): return w // 4
def src_pos(w): return w % 4
def p64_imm(p0, p1, p2=0, p3=0): return p0 | (p1 << 2) | (p2 << 4) | (p3 << 6)
def blend_mask_64(elements_from_b):
    mask = 0
    for e in elements_from_b:
        mask |= 0x03 << (e * 2)
    return mask

def gen_half(x, y):
    sx, px = src_vec(x), src_pos(x)
    sy, py = src_vec(y), src_pos(y)
    src_x, src_y = MSG_NAMES[sx], MSG_NAMES[sy]

    if sx == sy:
        imm = p64_imm(px, py)
        return f"Avx2.Permute4x64({src_x}, 0x{imm:02x})"
    if px == py:
        if px == 0:
            return f"Avx2.UnpackLow({src_x}, {src_y})"
        elif px == 1:
            return f"Avx2.UnpackHigh({src_x}, {src_y})"
        elif px == 2:
            expr = f"Avx2.UnpackLow({src_x}, {src_y})"
            imm = p64_imm(2, 3)
            return f"Avx2.Permute4x64({expr}, 0x{imm:02x})"
        else:
            expr = f"Avx2.UnpackHigh({src_x}, {src_y})"
            imm = p64_imm(2, 3)
            return f"Avx2.Permute4x64({expr}, 0x{imm:02x})"
    blend_elems_from_y = [py]
    mask = blend_mask_64(blend_elems_from_y)
    blend_expr = f"Avx2.Blend({src_x}.AsInt32(), {src_y}.AsInt32(), 0x{mask:02x}).AsUInt64()"
    imm = p64_imm(px, py)
    return f"Avx2.Permute4x64({blend_expr}, 0x{imm:02x})"

def gen_vector(a, b, c, d):
    lower_expr = gen_half(a, b)
    upper_expr = gen_half(c, d)
    return f"Avx2.Permute2x128({lower_expr}, {upper_expr}, 0x20)"

# ===== Simulation for verification =====
def sim_unpack_low(a, b): return [a[0], b[0], a[2], b[2]]
def sim_unpack_high(a, b): return [a[1], b[1], a[3], b[3]]
def sim_permute4x64(v, imm): return [v[(imm >> (i*2)) & 3] for i in range(4)]
def sim_permute2x128(a, b, imm):
    lanes = [a[:2], a[2:], b[:2], b[2:]]
    return lanes[imm & 3] + lanes[(imm >> 4) & 3]
def sim_blend32(a, b, mask):
    result = list(a)
    for i in range(4):
        lo_bit = (mask >> (2*i)) & 1
        hi_bit = (mask >> (2*i+1)) & 1
        if lo_bit and hi_bit:
            result[i] = b[i]
    return result

def split_args(s):
    args = []
    depth = 0
    current = ""
    for c in s:
        if c in ('(', '<'): depth += 1; current += c
        elif c in (')', '>'): depth -= 1; current += c
        elif c == ',' and depth == 0: args.append(current.strip()); current = ""
        else: current += c
    if current.strip(): args.append(current.strip())
    return args

def parse_int(s):
    s = s.strip()
    return int(s, 16) if s.startswith("0x") or s.startswith("0X") else int(s)

def sim_eval(expr, msgs):
    msg0, msg1, msg2, msg3 = msgs
    expr = expr.strip()
    if expr.startswith("Avx2.Permute2x128("):
        args = split_args(expr[len("Avx2.Permute2x128("):-1])
        return sim_permute2x128(sim_eval(args[0], msgs), sim_eval(args[1], msgs), parse_int(args[2]))
    if expr.startswith("Avx2.Permute4x64("):
        args = split_args(expr[len("Avx2.Permute4x64("):-1])
        return sim_permute4x64(sim_eval(args[0], msgs), parse_int(args[1]))
    if expr.startswith("Avx2.UnpackLow("):
        args = split_args(expr[len("Avx2.UnpackLow("):-1])
        return sim_unpack_low(sim_eval(args[0], msgs), sim_eval(args[1], msgs))
    if expr.startswith("Avx2.UnpackHigh("):
        args = split_args(expr[len("Avx2.UnpackHigh("):-1])
        return sim_unpack_high(sim_eval(args[0], msgs), sim_eval(args[1], msgs))
    if expr.startswith("Avx2.Blend("):
        inner = expr[len("Avx2.Blend("):]
        if inner.endswith(".AsUInt64()"): inner = inner[:-len(".AsUInt64()")]
        if inner.endswith(")"): inner = inner[:-1]
        args = split_args(inner)
        a_expr = args[0].replace(".AsInt32()", "")
        b_expr = args[1].replace(".AsInt32()", "")
        return sim_blend32(sim_eval(a_expr, msgs), sim_eval(b_expr, msgs), parse_int(args[2]))
    if expr == "msg0": return list(msg0)
    if expr == "msg1": return list(msg1)
    if expr == "msg2": return list(msg2)
    if expr == "msg3": return list(msg3)
    raise ValueError(f"Cannot evaluate: {expr}")


# ===== Generate all round code =====
print("Generating and verifying BLAKE2b AVX2 message loading...")
msgs = [[0,1,2,3], [4,5,6,7], [8,9,10,11], [12,13,14,15]]

all_code = {}
for rnd in range(10):
    sigma = SIGMA[rnd]
    vectors = {
        'col_b0': [sigma[0], sigma[2], sigma[4], sigma[6]],
        'col_b1': [sigma[1], sigma[3], sigma[5], sigma[7]],
        'diag_b0': [sigma[8], sigma[10], sigma[12], sigma[14]],
        'diag_b1': [sigma[9], sigma[11], sigma[13], sigma[15]],
    }
    round_exprs = {}
    for name, target in vectors.items():
        expr = gen_vector(*target)
        result = sim_eval(expr, msgs)
        assert result == target, f"Round {rnd} {name}: got {result}, expected {target}"
        round_exprs[name] = expr
    all_code[rnd] = round_exprs

print("All 10 unique rounds verified correct.")

# ===== Build round C# code =====
def build_round_code(rnd):
    """Build the C# code for one complete round."""
    actual = rnd % 10
    sigma = SIGMA[actual]
    code = all_code[actual]

    col_b0 = [sigma[0], sigma[2], sigma[4], sigma[6]]
    col_b1 = [sigma[1], sigma[3], sigma[5], sigma[7]]
    diag_b0 = [sigma[8], sigma[10], sigma[12], sigma[14]]
    diag_b1 = [sigma[9], sigma[11], sigma[13], sigma[15]]

    lines = []

    if rnd >= 10:
        lines.append(f"\t\t// ===== Round {rnd} (same as Round {actual}) =====")
    else:
        sigma_str = ",".join(str(s) for s in sigma)
        lines.append(f"\t\t// ===== Round {rnd} (sigma: {sigma_str}) =====")

    lines.append(f"\t\t// Column: b0=[w{col_b0[0]},w{col_b0[1]},w{col_b0[2]},w{col_b0[3]}], b1=[w{col_b1[0]},w{col_b1[1]},w{col_b1[2]},w{col_b1[3]}]")
    lines.append(f"\t\tb0 = {code['col_b0']};")
    lines.append(f"\t\tb1 = {code['col_b1']};")
    lines.append("\t\trow0 = Avx2.Add(Avx2.Add(row0, row1), b0);")
    lines.append("\t\trow3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();")
    lines.append("\t\trow2 = Avx2.Add(row2, row3);")
    lines.append("\t\trow1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();")
    lines.append("\t\trow0 = Avx2.Add(Avx2.Add(row0, row1), b1);")
    lines.append("\t\trow3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();")
    lines.append("\t\trow2 = Avx2.Add(row2, row3);")
    lines.append("\t\tt0 = Avx2.Xor(row1, row2);")
    lines.append("\t\trow1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));")

    lines.append("\t\t// Diagonalize")
    lines.append("\t\trow1 = Avx2.Permute4x64(row1, 0x39);")
    lines.append("\t\trow2 = Avx2.Permute4x64(row2, 0x4E);")
    lines.append("\t\trow3 = Avx2.Permute4x64(row3, 0x93);")

    lines.append(f"\t\t// Diagonal: b0=[w{diag_b0[0]},w{diag_b0[1]},w{diag_b0[2]},w{diag_b0[3]}], b1=[w{diag_b1[0]},w{diag_b1[1]},w{diag_b1[2]},w{diag_b1[3]}]")
    lines.append(f"\t\tb0 = {code['diag_b0']};")
    lines.append(f"\t\tb1 = {code['diag_b1']};")
    lines.append("\t\trow0 = Avx2.Add(Avx2.Add(row0, row1), b0);")
    lines.append("\t\trow3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();")
    lines.append("\t\trow2 = Avx2.Add(row2, row3);")
    lines.append("\t\trow1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();")
    lines.append("\t\trow0 = Avx2.Add(Avx2.Add(row0, row1), b1);")
    lines.append("\t\trow3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();")
    lines.append("\t\trow2 = Avx2.Add(row2, row3);")
    lines.append("\t\tt0 = Avx2.Xor(row1, row2);")
    lines.append("\t\trow1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));")

    lines.append("\t\t// Undiagonalize")
    lines.append("\t\trow1 = Avx2.Permute4x64(row1, 0x93);")
    lines.append("\t\trow2 = Avx2.Permute4x64(row2, 0x4E);")
    lines.append("\t\trow3 = Avx2.Permute4x64(row3, 0x39);")

    return "\n".join(lines)


# Build complete rounds section
all_rounds = []
for rnd in range(12):
    all_rounds.append(build_round_code(rnd))
rounds_code = "\n\n".join(all_rounds)


# ===== Patch Blake2b.cs =====
FILE = r"C:\Users\me\source\repos\StreamHash\src\StreamHash.Core\Blake2b.cs"

with open(FILE, "r", encoding="utf-8-sig") as f:
    content = f.read()

# Find the variable declaration line (just before first round)
var_decl = "\tVector256<ulong> b0, b1, t0, t1;\n"
var_decl_idx = content.find(var_decl)
if var_decl_idx < 0:
    # Try without t1
    var_decl = "\tVector256<ulong> b0, b1, t0;\n"
    var_decl_idx = content.find(var_decl)

assert var_decl_idx >= 0, "Cannot find variable declaration"

# Start of rounds = right after the variable declaration + newline
rounds_start = var_decl_idx + len(var_decl)

# Find end of rounds = the finalize comment
finalize_marker = "\t// Finalize: XOR upper and lower halves"
finalize_idx = content.find(finalize_marker, rounds_start)
assert finalize_idx >= 0, "Cannot find finalize marker"

# Replace rounds section
# Keep a blank line before the first round and before finalize
new_content = content[:rounds_start] + "\n" + rounds_code + "\n\n" + content[finalize_idx:]

# Update variable declaration to remove t1 if it exists (not needed in new code)
new_content = new_content.replace(
    "Vector256<ulong> b0, b1, t0, t1;",
    "Vector256<ulong> b0, b1, t0;"
)

with open(FILE, "w", encoding="utf-8-sig", newline="\r\n") as f:
    f.write(new_content)

print(f"Patched {FILE}")
print(f"Replaced {finalize_idx - rounds_start} chars of round code with {len(rounds_code)} chars")
