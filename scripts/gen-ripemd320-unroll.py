#!/usr/bin/env python3
"""Generate fully unrolled RIPEMD-320 ProcessBlock code.

Eliminates loop overhead and bounds-checked array lookups for RL/RR/SL/SR tables.
All message word indices and rotation amounts become compile-time constants.
"""

RL = [
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
]
RR = [
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
]
SL = [
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
]
SR = [
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
]

# Round function expressions (left, right)
# Left: F0, F1, F2, F3, F4
# Right: F4, F3, F2, F1, F0
LEFT_F = [
	"(bl ^ cl ^ dl)",                 # F0
	"((bl & cl) | (~bl & dl))",       # F1
	"((bl | ~cl) ^ dl)",              # F2
	"((bl & dl) | (cl & ~dl))",       # F3
	"(bl ^ (cl | ~dl))",              # F4
]
RIGHT_F = [
	"(br ^ (cr | ~dr))",              # F4
	"((br & dr) | (cr & ~dr))",       # F3
	"((br | ~cr) ^ dr)",              # F2
	"((br & cr) | (~br & dr))",       # F1
	"(br ^ cr ^ dr)",                 # F0
]

# Round constants
LEFT_K = [
	"",                    # Round 0: no constant
	" + 0x5a827999u",     # Round 1
	" + 0x6ed9eba1u",     # Round 2
	" + 0x8f1bbcdcu",     # Round 3
	" + 0xa953fd4eu",     # Round 4
]
RIGHT_K = [
	" + 0x50a28be6u",     # Round 0
	" + 0x5c4dd124u",     # Round 1
	" + 0x6d703ef3u",     # Round 2
	" + 0x7a6d76e9u",     # Round 3
	"",                    # Round 4: no constant
]

# Exchanges after each round
EXCHANGES = [
	"(bl, br) = (br, bl);",   # After Round 0
	"(dl, dr) = (dr, dl);",   # After Round 1
	"(al, ar) = (ar, al);",   # After Round 2
	"(cl, cr) = (cr, cl);",   # After Round 3
	"(el, er) = (er, el);",   # After Round 4
]

ROUND_NAMES = ["Round 0", "Round 1", "Round 2", "Round 3", "Round 4"]
EXCHANGE_NAMES = ["B", "D", "A", "C", "E"]

def main():
	lines = []

	# Message word loading
	lines.append("\t\t// Load message words (little-endian) via direct unaligned reads")
	lines.append("\t\tref byte blockRef = ref MemoryMarshal.GetReference(block);")
	for i in range(16):
		lines.append(f"\t\tuint x{i} = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref blockRef, {i * 4}));")

	lines.append("")
	lines.append("\t\t// Initialize working variables")
	lines.append("\t\tuint al = _stateLeft[0], bl = _stateLeft[1], cl = _stateLeft[2], dl = _stateLeft[3], el = _stateLeft[4];")
	lines.append("\t\tuint ar = _stateRight[0], br = _stateRight[1], cr = _stateRight[2], dr = _stateRight[3], er = _stateRight[4];")
	lines.append("")
	lines.append("\t\tuint tl, tr;")

	for round_idx in range(5):
		start = round_idx * 16
		end = start + 16
		lf = LEFT_F[round_idx]
		rf = RIGHT_F[round_idx]
		lk = LEFT_K[round_idx]
		rk = RIGHT_K[round_idx]

		lines.append("")
		lines.append(f"\t\t// {ROUND_NAMES[round_idx]} (steps {start}-{end - 1})")

		for j in range(start, end):
			rl = RL[j]
			rr = RR[j]
			sl = SL[j]
			sr = SR[j]

			# Left line
			lines.append(f"\t\ttl = uint.RotateLeft(al + {lf} + x{rl}{lk}, {sl}) + el;")
			lines.append(f"\t\tal = el; el = dl; dl = uint.RotateLeft(cl, 10); cl = bl; bl = tl;")

			# Right line
			lines.append(f"\t\ttr = uint.RotateLeft(ar + {rf} + x{rr}{rk}, {sr}) + er;")
			lines.append(f"\t\tar = er; er = dr; dr = uint.RotateLeft(cr, 10); cr = br; br = tr;")

		lines.append(f"\t\t// Exchange {EXCHANGE_NAMES[round_idx]} after {ROUND_NAMES[round_idx].lower()}")
		lines.append(f"\t\t{EXCHANGES[round_idx]}")

	lines.append("")
	lines.append("\t\t// Update state")
	lines.append("\t\t_stateLeft[0] += al; _stateLeft[1] += bl; _stateLeft[2] += cl; _stateLeft[3] += dl; _stateLeft[4] += el;")
	lines.append("\t\t_stateRight[0] += ar; _stateRight[1] += br; _stateRight[2] += cr; _stateRight[3] += dr; _stateRight[4] += er;")

	output = "\n".join(lines)
	print(output)
	print(f"\n// Total steps: {5 * 16} (80 left + 80 right = 160 operations)")

if __name__ == "__main__":
	main()
