#!/usr/bin/env python3
"""Generate fully unrolled RIPEMD-128 ProcessBlock code."""

RL = [
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
]

RR = [
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
]

SL = [
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
]

SR = [
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
]

# Boolean functions as inline C# expressions
# F0(x,y,z) = x ^ y ^ z
# F1(x,y,z) = (x & y) | (~x & z)
# F2(x,y,z) = (x | ~y) ^ z
# F3(x,y,z) = (x & z) | (y & ~z)

def f_expr(fn, b, c, d):
	if fn == 0:
		return f"({b} ^ {c} ^ {d})"
	elif fn == 1:
		return f"(({b} & {c}) | (~{b} & {d}))"
	elif fn == 2:
		return f"(({b} | ~{c}) ^ {d})"
	elif fn == 3:
		return f"(({b} & {d}) | ({c} & ~{d}))"

# Round configurations: (left_fn, left_k, right_fn, right_k)
rounds = [
	(0, None, 3, "0x50a28be6u"),
	(1, "0x5a827999u", 2, "0x5c4dd124u"),
	(2, "0x6ed9eba1u", 1, "0x6d703ef3u"),
	(3, "0x8f1bbcdcu", 0, None),
]


def gen_instance_processblock():
	"""Generate the instance ProcessBlock method."""
	lines = []
	lines.append("\t[MethodImpl(MethodImplOptions.AggressiveOptimization)]")
	lines.append("\t[SkipLocalsInit]")
	lines.append("\tprivate void ProcessBlock(ReadOnlySpan<byte> block) {")
	lines.append("\t\t// Load message words (little-endian) via direct unaligned reads")
	lines.append("\t\tref byte blockRef = ref MemoryMarshal.GetReference(block);")
	for i in range(16):
		lines.append(f"\t\tuint x{i} = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, {i * 4}));")
	lines.append("")
	lines.append("\t\t// Initialize working variables for both parallel lines from the same state")
	lines.append("\t\tuint al = _state[0], bl = _state[1], cl = _state[2], dl = _state[3];")
	lines.append("\t\tuint ar = _state[0], br = _state[1], cr = _state[2], dr = _state[3];")
	lines.append("")
	lines.append("\t\tuint tl, tr;")

	for round_idx in range(4):
		left_fn, left_k, right_fn, right_k = rounds[round_idx]
		lines.append("")
		lines.append(f"\t\t// Round {round_idx} (steps {round_idx*16}-{round_idx*16+15})")
		for step in range(16):
			j = round_idx * 16 + step
			lw = RL[j]
			rw = RR[j]
			ls = SL[j]
			rs = SR[j]

			# Left line
			fl = f_expr(left_fn, "bl", "cl", "dl")
			lk = f" + {left_k}" if left_k else ""
			lines.append(f"\t\ttl = uint.RotateLeft(al + {fl} + x{lw}{lk}, {ls});")
			lines.append(f"\t\tal = dl; dl = cl; cl = bl; bl = tl;")

			# Right line
			fr = f_expr(right_fn, "br", "cr", "dr")
			rk = f" + {right_k}" if right_k else ""
			lines.append(f"\t\ttr = uint.RotateLeft(ar + {fr} + x{rw}{rk}, {rs});")
			lines.append(f"\t\tar = dr; dr = cr; cr = br; br = tr;")

	lines.append("")
	lines.append("\t\t// Combine both parallel lines with circular shift finalization")
	lines.append("\t\tuint t = _state[1] + cl + dr;")
	lines.append("\t\t_state[1] = _state[2] + dl + ar;")
	lines.append("\t\t_state[2] = _state[3] + al + br;")
	lines.append("\t\t_state[3] = _state[0] + bl + cr;")
	lines.append("\t\t_state[0] = t;")
	lines.append("\t}")
	return "\n".join(lines)


def gen_static_processblock():
	"""Generate the static ProcessBlockStatic method."""
	lines = []
	lines.append("\t[MethodImpl(MethodImplOptions.AggressiveOptimization)]")
	lines.append("\t[SkipLocalsInit]")
	lines.append("\tprivate static void ProcessBlockStatic(ReadOnlySpan<byte> block, Span<uint> state) {")
	lines.append("\t\t// Load message words (little-endian) via direct unaligned reads")
	lines.append("\t\tref byte blockRef = ref MemoryMarshal.GetReference(block);")
	for i in range(16):
		lines.append(f"\t\tuint x{i} = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, {i * 4}));")
	lines.append("")
	lines.append("\t\tuint al = state[0], bl = state[1], cl = state[2], dl = state[3];")
	lines.append("\t\tuint ar = state[0], br = state[1], cr = state[2], dr = state[3];")
	lines.append("")
	lines.append("\t\tuint tl, tr;")

	for round_idx in range(4):
		left_fn, left_k, right_fn, right_k = rounds[round_idx]
		lines.append("")
		lines.append(f"\t\t// Round {round_idx} (steps {round_idx*16}-{round_idx*16+15})")
		for step in range(16):
			j = round_idx * 16 + step
			lw = RL[j]
			rw = RR[j]
			ls = SL[j]
			rs = SR[j]

			fl = f_expr(left_fn, "bl", "cl", "dl")
			lk = f" + {left_k}" if left_k else ""
			lines.append(f"\t\ttl = uint.RotateLeft(al + {fl} + x{lw}{lk}, {ls});")
			lines.append(f"\t\tal = dl; dl = cl; cl = bl; bl = tl;")

			fr = f_expr(right_fn, "br", "cr", "dr")
			rk = f" + {right_k}" if right_k else ""
			lines.append(f"\t\ttr = uint.RotateLeft(ar + {fr} + x{rw}{rk}, {rs});")
			lines.append(f"\t\tar = dr; dr = cr; cr = br; br = tr;")

	lines.append("")
	lines.append("\t\t// Combine both parallel lines with circular shift finalization")
	lines.append("\t\tuint t = state[1] + cl + dr;")
	lines.append("\t\tstate[1] = state[2] + dl + ar;")
	lines.append("\t\tstate[2] = state[3] + al + br;")
	lines.append("\t\tstate[3] = state[0] + bl + cr;")
	lines.append("\t\tstate[0] = t;")
	lines.append("\t}")
	return "\n".join(lines)


if __name__ == "__main__":
	print("// ========== Instance ProcessBlock (fully unrolled) ==========")
	print()
	print(gen_instance_processblock())
	print()
	print("// ========== Static ProcessBlockStatic (fully unrolled) ==========")
	print()
	print(gen_static_processblock())
