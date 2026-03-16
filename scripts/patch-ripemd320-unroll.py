#!/usr/bin/env python3
"""Patch Ripemd320.cs to replace loop-based ProcessBlock with fully unrolled version."""

import sys
from pathlib import Path

RIPEMD_CS = Path(__file__).parent.parent / "src" / "StreamHash.Core" / "Ripemd320.cs"
OUTPUT_FILE = Path(__file__).parent / "ripemd320-unroll-output.txt"

def main():
	source = RIPEMD_CS.read_text(encoding="utf-8-sig")
	generated = OUTPUT_FILE.read_text(encoding="utf-8-sig")

	# Extract the generated body (everything except the trailing comment)
	gen_lines = [l for l in generated.split("\n") if not l.startswith("// Total steps:")]
	generated_body = "\n".join(gen_lines).rstrip()

	# Find the ProcessBlock method body
	# Look for the method signature
	method_sig = "private void ProcessBlock(ReadOnlySpan<byte> block) {"
	method_start = source.find(method_sig)
	if method_start < 0:
		print("ERROR: Could not find ProcessBlock method")
		sys.exit(1)

	# Find the opening brace
	body_start = source.find("{", method_start + len("private void ProcessBlock")) + 1

	# Find the matching closing brace - count braces
	depth = 1
	pos = body_start
	while depth > 0 and pos < len(source):
		if source[pos] == "{":
			depth += 1
		elif source[pos] == "}":
			depth -= 1
		pos += 1

	body_end = pos - 1  # Position of the closing brace

	# The new body content should be between { and }
	new_body = "\n" + generated_body + "\n\t"

	source = source[:body_start] + new_body + source[body_end:]

	# Remove the old RotateLeft wrapper and round function methods since we no longer need them
	# Actually, keep them for now — they may be referenced by factory code

	# Also remove the static readonly arrays that are no longer needed by ProcessBlock
	# RL, RR, SL, SR are still referenced by the instance ProcessBlock? No, they're used in the loop version.
	# But they might be referenced elsewhere. Keep them for safety.

	RIPEMD_CS.write_text(source, encoding="utf-8-sig")
	print("SUCCESS: Patched ProcessBlock with fully unrolled code")

	# Verify
	count = source.count("uint.RotateLeft")
	print(f"  uint.RotateLeft occurrences: {count}")
	count_x = len([l for l in source.split("\n") if "Unsafe.ReadUnaligned<uint>" in l and "blockRef" in l])
	print(f"  Direct message reads (x0-x15): {count_x}")

if __name__ == "__main__":
	main()
