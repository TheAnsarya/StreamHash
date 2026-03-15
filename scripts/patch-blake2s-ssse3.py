#!/usr/bin/env python3
"""Patch Blake2b.cs to replace scalar message loading in CompressSsse3 with vector loads + SSE shuffles."""

import re
import sys
from pathlib import Path

BLAKE2B_CS = Path(__file__).parent.parent / "src" / "StreamHash.Core" / "Blake2b.cs"
OUTPUT_FILE = Path(__file__).parent / "blake2s-ssse3-output.txt"

def main():
	source = BLAKE2B_CS.read_text(encoding="utf-8-sig")
	generated = OUTPUT_FILE.read_text(encoding="utf-8-sig")

	# Extract the generated round code (from "// Round 0" to "// All 10 rounds")
	gen_start = generated.find("\t\t// Round 0 - Column phase")
	gen_end = generated.find("\n// All 10 rounds")
	if gen_start < 0 or gen_end < 0:
		print("ERROR: Could not find generated round code boundaries")
		sys.exit(1)
	generated_rounds = generated[gen_start:gen_end].rstrip()

	# Find CompressSsse3 method
	method_match = re.search(r'private void CompressSsse3\(ReadOnlySpan<byte> block, bool isFinal\) \{', source)
	if not method_match:
		print("ERROR: Could not find CompressSsse3 method")
		sys.exit(1)

	method_start = method_match.start()

	# Find the scalar reads section (from "// Parse message" to first "// Byte shuffle")
	scalar_start = source.find("// Parse message block into 16 32-bit local variables", method_start)
	scalar_end = source.find("// Byte shuffle masks for 32-bit rotations", method_start)
	if scalar_start < 0 or scalar_end < 0:
		print("ERROR: Could not find scalar reads section")
		sys.exit(1)

	# Find the start of line containing the comment
	scalar_line_start = source.rfind("\n", 0, scalar_start) + 1

	# Replace scalar reads with vector loads
	new_message_loading = (
		"\t\t// Load message block as 4 vector registers (replaces 16 scalar reads)\n"
		"\t\tref byte blockRef = ref MemoryMarshal.GetReference(block);\n"
		"\t\tvar msg0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref blockRef);\n"
		"\t\tvar msg1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref blockRef, 16));\n"
		"\t\tvar msg2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref blockRef, 32));\n"
		"\t\tvar msg3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.Add(ref blockRef, 48));\n"
	)

	source = source[:scalar_line_start] + new_message_loading + source[scalar_end:]

	# Now add tt, tu to the variable declaration
	old_decl = "Vector128<uint> b0, b1, t0;"
	new_decl = "Vector128<uint> b0, b1, t0, tt, tu;"
	if old_decl not in source:
		print("ERROR: Could not find variable declaration")
		sys.exit(1)
	source = source.replace(old_decl, new_decl, 1)

	# Find all 10 rounds section and replace
	# Find first "// Round 0 - Column phase" after CompressSsse3
	method_pos = source.find("CompressSsse3")
	rounds_start = source.find("\t\t// Round 0 - Column phase", method_pos)
	if rounds_start < 0:
		print("ERROR: Could not find Round 0 start")
		sys.exit(1)

	# Find the finalize section start (first non-round line after Round 9)
	# Look for "// Finalize:" after the rounds
	finalize_marker = source.find("// Finalize: XOR upper and lower halves", rounds_start)
	if finalize_marker < 0:
		print("ERROR: Could not find finalize section")
		sys.exit(1)

	# Back up to the newline before finalize
	finalize_line_start = source.rfind("\n", 0, finalize_marker) + 1

	source = source[:rounds_start] + generated_rounds + "\n" + source[finalize_line_start:]

	# Write back
	BLAKE2B_CS.write_text(source, encoding="utf-8-sig")
	print("SUCCESS: Patched CompressSsse3 with vector message loading")

	# Verify round count
	round_count = len(re.findall(r"// Round \d+ - Column phase", source[source.find("CompressSsse3"):]))
	print(f"  Rounds found: {round_count}")

	# Count shuffle instructions
	shuffle_count = len(re.findall(r"Sse\.Shuffle\(", source[source.find("CompressSsse3"):]))
	print(f"  Sse.Shuffle calls in CompressSsse3: {shuffle_count}")

if __name__ == "__main__":
	main()
