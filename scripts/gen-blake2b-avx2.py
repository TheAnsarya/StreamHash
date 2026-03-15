#!/usr/bin/env python3
"""Generate correct BLAKE2b AVX2 message loading C# code.

Systematically generates message vector construction code using AVX2 intrinsics,
guaranteed correct by construction from the sigma schedule.
"""

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

# Source vectors: msg0=[w0..w3], msg1=[w4..w7], msg2=[w8..w11], msg3=[w12..w15]
MSG_NAMES = ["msg0", "msg1", "msg2", "msg3"]

def src_vec(w):
    """Which source vector contains word w"""
    return w // 4

def src_pos(w):
    """Position within source vector for word w"""
    return w % 4

def p64_imm(p0, p1, p2=0, p3=0):
    """Compute Permute4x64 immediate: output[i] = input[pi]"""
    return p0 | (p1 << 2) | (p2 << 4) | (p3 << 6)

def blend_mask_64(elements_from_b):
    """Compute Blend mask at 32-bit granularity for 64-bit elements from second operand"""
    mask = 0
    for e in elements_from_b:
        mask |= 0x03 << (e * 2)
    return mask

def gen_half(x, y, for_upper=False):
    """Generate code to create [x, y] as the lower 128 bits of a vector.

    Returns (code_lines, result_var_name) where the lower 128 bits of result_var_name
    contain [x, y]. If for_upper is True, the [x,y] might be in the upper 128 bits
    (caller will use appropriate Permute2x128 control byte).
    """
    sx, px = src_vec(x), src_pos(x)
    sy, py = src_vec(y), src_pos(y)

    src_x = MSG_NAMES[sx]
    src_y = MSG_NAMES[sy]

    if sx == sy:
        # Both from same source - simple Permute4x64
        imm = p64_imm(px, py)
        return [f"Avx2.Permute4x64({src_x}, 0x{imm:02x})"], "lower128"

    if px == py:
        # Same position in different sources
        if px == 0:
            # UnpackLow gives [src_x[0], src_y[0], src_x[2], src_y[2]]
            # lower 128 = [src_x[0], src_y[0]] ✓
            return [f"Avx2.UnpackLow({src_x}, {src_y})"], "unpack_lo_lane0"
        elif px == 1:
            # UnpackHigh gives [src_x[1], src_y[1], src_x[3], src_y[3]]
            # lower 128 = [src_x[1], src_y[1]] ✓
            return [f"Avx2.UnpackHigh({src_x}, {src_y})"], "unpack_hi_lane0"
        elif px == 2:
            # UnpackLow gives [.., .., src_x[2], src_y[2]]
            # upper 128 = [src_x[2], src_y[2]]
            # Need Permute4x64 to move to lower half, OR use Permute2x128 with upper lane
            expr = f"Avx2.UnpackLow({src_x}, {src_y})"
            imm = p64_imm(2, 3)  # move upper to lower
            return [f"Avx2.Permute4x64({expr}, 0x{imm:02x})"], "perm_unpack"
        else:  # px == 3
            expr = f"Avx2.UnpackHigh({src_x}, {src_y})"
            imm = p64_imm(2, 3)
            return [f"Avx2.Permute4x64({expr}, 0x{imm:02x})"], "perm_unpack"

    # Different sources, different positions
    # Strategy: Blend + Permute4x64
    # Blend src_x and src_y to get x at position px and y at position py in one vector
    # Then Permute4x64 to [x, y, ?, ?]
    blend_elems_from_y = [py]  # Take element at py from src_y
    mask = blend_mask_64(blend_elems_from_y)
    blend_expr = f"Avx2.Blend({src_x}.AsInt32(), {src_y}.AsInt32(), 0x{mask:02x}).AsUInt64()"
    # After blend: result[px] = x (from src_x), result[py] = y (from src_y)
    imm = p64_imm(px, py)
    return [f"Avx2.Permute4x64({blend_expr}, 0x{imm:02x})"], "blend_perm"


def gen_vector(a, b, c, d):
    """Generate code to create [a, b, c, d] as a Vector256<ulong>.

    Returns C# expression string.
    """
    # Check if we can use UnpackLow/High + Permute4x64 for the full vector
    # This works when all 4 elements come from 2 source vectors in the right pattern

    sa, pa = src_vec(a), src_pos(a)
    sb, pb = src_vec(b), src_pos(b)
    sc, pc = src_vec(c), src_pos(c)
    sd, pd = src_vec(d), src_pos(d)

    src_a, src_b = MSG_NAMES[sa], MSG_NAMES[sb]
    src_c, src_d = MSG_NAMES[sc], MSG_NAMES[sd]

    # Special case: all from same 2 sources with UnpackLow/High pattern
    if sa == sc and sb == sd and pa == pc and pb == pd:
        # Check if UnpackLow can produce [a, b, c, d] with a permute
        # UnpackLow(X, Y) = [X[0], Y[0], X[2], Y[2]]
        if (pa % 2 == 0) and (pb % 2 == 0):
            # a at even pos in sa, c at even pos in sa => UnpackLow territory
            expr = f"Avx2.UnpackLow({src_a}, {src_b})"
            # UnpackLow gives [src_a[0], src_b[0], src_a[2], src_b[2]]
            # We need to map: a=src_a[pa], b=src_b[pb], c=src_a[pc], d=src_b[pd]
            # In UnpackLow result: src_a[0]->pos0, src_b[0]->pos1, src_a[2]->pos2, src_b[2]->pos3
            # Find where a,b,c,d are in the unpack result
            pass  # Fall through to general approach

    # General approach: build lower half [a,b] and upper half [c,d] separately,
    # combine with Permute2x128

    lower_code, lower_type = gen_half(a, b)
    upper_code, upper_type = gen_half(c, d)

    # Determine Permute2x128 control byte
    # Default: lower from first arg's lower lane (0), upper from second arg's lower lane (2)
    # = (2 << 4) | 0 = 0x20
    p2_ctl = 0x20

    # Special case: if upper half is in the UPPER 128 of the unpack result, use upper lane
    # This happens when gen_half returns an unpack where the result is in positions 2,3
    if upper_type in ("unpack_lo_lane0", "unpack_hi_lane0"):
        # lower 128 of upper has our [c, d]
        p2_ctl = 0x20

    lower_expr = lower_code[0]
    upper_expr = upper_code[0]

    return f"Avx2.Permute2x128({lower_expr}, {upper_expr}, 0x{p2_ctl:02x})"


def verify_gen_half(x, y, code):
    """Verify that the generated half code produces [x, y]"""
    # Simulate the operations
    msgs = [[0,1,2,3], [4,5,6,7], [8,9,10,11], [12,13,14,15]]
    # We'd need to parse and evaluate the expression... skip for now
    pass

# ===== Simulation functions for verification =====
def sim_unpack_low(a, b):
    return [a[0], b[0], a[2], b[2]]

def sim_unpack_high(a, b):
    return [a[1], b[1], a[3], b[3]]

def sim_permute4x64(v, imm):
    return [v[(imm >> (i*2)) & 3] for i in range(4)]

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

def sim_eval(expr, msgs):
    """Evaluate a message loading expression and return the resulting vector."""
    msg0, msg1, msg2, msg3 = msgs

    # Parse simple expressions
    expr = expr.strip()

    # Handle Avx2.Permute2x128(A, B, ctl)
    if expr.startswith("Avx2.Permute2x128("):
        # Find the matching closing paren
        inner = expr[len("Avx2.Permute2x128("):]
        # Need to parse nested function calls
        args = split_args(inner[:-1])
        a = sim_eval(args[0], msgs)
        b = sim_eval(args[1], msgs)
        ctl = parse_int(args[2])
        return sim_permute2x128(a, b, ctl)

    if expr.startswith("Avx2.Permute4x64("):
        inner = expr[len("Avx2.Permute4x64("):]
        args = split_args(inner[:-1])
        v = sim_eval(args[0], msgs)
        imm = parse_int(args[1])
        return sim_permute4x64(v, imm)

    if expr.startswith("Avx2.UnpackLow("):
        inner = expr[len("Avx2.UnpackLow("):]
        args = split_args(inner[:-1])
        a = sim_eval(args[0], msgs)
        b = sim_eval(args[1], msgs)
        return sim_unpack_low(a, b)

    if expr.startswith("Avx2.UnpackHigh("):
        inner = expr[len("Avx2.UnpackHigh("):]
        args = split_args(inner[:-1])
        a = sim_eval(args[0], msgs)
        b = sim_eval(args[1], msgs)
        return sim_unpack_high(a, b)

    if expr.startswith("Avx2.Blend("):
        inner = expr[len("Avx2.Blend("):]
        # Remove .AsUInt64() at the end if present
        if inner.endswith(".AsUInt64()"):
            inner = inner[:-len(".AsUInt64()")]
        if inner.endswith(")"):
            inner = inner[:-1]
        args = split_args(inner)
        # Remove .AsInt32() from args
        a_expr = args[0].replace(".AsInt32()", "")
        b_expr = args[1].replace(".AsInt32()", "")
        a = sim_eval(a_expr, msgs)
        b = sim_eval(b_expr, msgs)
        mask = parse_int(args[2])
        return sim_blend32(a, b, mask)

    # Source vectors
    if expr == "msg0": return list(msg0)
    if expr == "msg1": return list(msg1)
    if expr == "msg2": return list(msg2)
    if expr == "msg3": return list(msg3)

    raise ValueError(f"Cannot evaluate: {expr}")

def split_args(s):
    """Split comma-separated args respecting nested parentheses."""
    args = []
    depth = 0
    current = ""
    for c in s:
        if c == '(' or c == '<':
            depth += 1
            current += c
        elif c == ')' or c == '>':
            depth -= 1
            current += c
        elif c == ',' and depth == 0:
            args.append(current.strip())
            current = ""
        else:
            current += c
    if current.strip():
        args.append(current.strip())
    return args

def parse_int(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


# Generate and verify all rounds
print("=== Generating and verifying BLAKE2b AVX2 message loading ===\n")
msgs = [[0,1,2,3], [4,5,6,7], [8,9,10,11], [12,13,14,15]]

all_ok = True
all_code = {}

for rnd in range(10):
    sigma = SIGMA[rnd]
    # Column phase: b0=[sigma[0],sigma[2],sigma[4],sigma[6]], b1=[sigma[1],sigma[3],sigma[5],sigma[7]]
    col_b0_target = [sigma[0], sigma[2], sigma[4], sigma[6]]
    col_b1_target = [sigma[1], sigma[3], sigma[5], sigma[7]]
    # Diagonal phase: b0=[sigma[8],sigma[10],sigma[12],sigma[14]], b1=[sigma[9],sigma[11],sigma[13],sigma[15]]
    diag_b0_target = [sigma[8], sigma[10], sigma[12], sigma[14]]
    diag_b1_target = [sigma[9], sigma[11], sigma[13], sigma[15]]

    vectors = {
        'col_b0': col_b0_target,
        'col_b1': col_b1_target,
        'diag_b0': diag_b0_target,
        'diag_b1': diag_b1_target,
    }

    round_code = {}
    for name, target in vectors.items():
        expr = gen_vector(*target)
        try:
            result = sim_eval(expr, msgs)
            if result == target:
                status = "OK"
            else:
                status = f"FAIL: got {result}"
                all_ok = False
        except Exception as e:
            status = f"ERROR: {e}"
            all_ok = False
            result = None

        round_code[name] = expr
        if status != "OK":
            print(f"  Round {rnd} {name}: target={target}, {status}")
            print(f"    expr: {expr}")

    all_code[rnd] = round_code

print()
if all_ok:
    print("ALL ROUNDS VERIFIED CORRECT!\n")
else:
    print("ERRORS FOUND\n")

# Print the C# code for all rounds
print("=== Generated C# code ===\n")
for rnd in range(12):
    actual_rnd = rnd % 10
    sigma = SIGMA[rnd]
    code = all_code[actual_rnd]

    sigma_str = ",".join(str(s) for s in sigma)
    col_b0 = [sigma[0], sigma[2], sigma[4], sigma[6]]
    col_b1 = [sigma[1], sigma[3], sigma[5], sigma[7]]
    diag_b0 = [sigma[8], sigma[10], sigma[12], sigma[14]]
    diag_b1 = [sigma[9], sigma[11], sigma[13], sigma[15]]

    if rnd >= 10:
        print(f"\t\t// ===== Round {rnd} (same as Round {actual_rnd}) =====")
    else:
        print(f"\t\t// ===== Round {rnd} (sigma: {sigma_str}) =====")

    # Column
    print(f"\t\t// Column: b0=[w{col_b0[0]},w{col_b0[1]},w{col_b0[2]},w{col_b0[3]}], b1=[w{col_b1[0]},w{col_b1[1]},w{col_b1[2]},w{col_b1[3]}]")
    print(f"\t\tb0 = {code['col_b0']};")
    print(f"\t\tb1 = {code['col_b1']};")

    # G function template
    print("\t\trow0 = Avx2.Add(Avx2.Add(row0, row1), b0);")
    print("\t\trow3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();")
    print("\t\trow2 = Avx2.Add(row2, row3);")
    print("\t\trow1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();")
    print("\t\trow0 = Avx2.Add(Avx2.Add(row0, row1), b1);")
    print("\t\trow3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();")
    print("\t\trow2 = Avx2.Add(row2, row3);")
    print("\t\tt0 = Avx2.Xor(row1, row2);")
    print("\t\trow1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));")

    # Diagonalize
    print("\t\t// Diagonalize")
    print("\t\trow1 = Avx2.Permute4x64(row1, 0x39);")
    print("\t\trow2 = Avx2.Permute4x64(row2, 0x4E);")
    print("\t\trow3 = Avx2.Permute4x64(row3, 0x93);")

    # Diagonal
    print(f"\t\t// Diagonal: b0=[w{diag_b0[0]},w{diag_b0[1]},w{diag_b0[2]},w{diag_b0[3]}], b1=[w{diag_b1[0]},w{diag_b1[1]},w{diag_b1[2]},w{diag_b1[3]}]")
    print(f"\t\tb0 = {code['diag_b0']};")
    print(f"\t\tb1 = {code['diag_b1']};")

    print("\t\trow0 = Avx2.Add(Avx2.Add(row0, row1), b0);")
    print("\t\trow3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();")
    print("\t\trow2 = Avx2.Add(row2, row3);")
    print("\t\trow1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();")
    print("\t\trow0 = Avx2.Add(Avx2.Add(row0, row1), b1);")
    print("\t\trow3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();")
    print("\t\trow2 = Avx2.Add(row2, row3);")
    print("\t\tt0 = Avx2.Xor(row1, row2);")
    print("\t\trow1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));")

    # Undiagonalize
    print("\t\t// Undiagonalize")
    print("\t\trow1 = Avx2.Permute4x64(row1, 0x93);")
    print("\t\trow2 = Avx2.Permute4x64(row2, 0x4E);")
    print("\t\trow3 = Avx2.Permute4x64(row3, 0x39);")
    print()
