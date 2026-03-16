#!/usr/bin/env python3
"""Patch Ripemd128.cs with fully unrolled ProcessBlock methods."""
import re

RIPEMD128_PATH = r"src\StreamHash.Core\Ripemd128.cs"
OUTPUT_PATH = r"scripts\ripemd128-unroll-output.txt"

with open(RIPEMD128_PATH, "r", encoding="utf-8-sig") as f:
	original = f.read()

with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
	generated = f.read()

# Extract instance method from generated output
instance_start = generated.index("\t[MethodImpl(MethodImplOptions.AggressiveOptimization)]\n\t[SkipLocalsInit]\n\tprivate void ProcessBlock")
instance_end = generated.index("\n\n// ========== Static")
instance_method = generated[instance_start:instance_end]

# Extract static method from generated output
static_start = generated.index("\t[MethodImpl(MethodImplOptions.AggressiveOptimization)]\n\t[SkipLocalsInit]\n\tprivate static void ProcessBlockStatic")
static_method = generated[static_start:].rstrip()

# 1. Remove the lookup tables from the Ripemd128Digest class
# Remove RL, RR, SL, SR arrays
original = re.sub(
	r'\t// Message word selection for the left line.*?\];\n',
	'', original, flags=re.DOTALL, count=1)
original = re.sub(
	r'\t// Message word selection for the right line.*?\];\n',
	'', original, flags=re.DOTALL, count=1)
original = re.sub(
	r'\t// Rotation amounts for the left line.*?\];\n',
	'', original, flags=re.DOTALL, count=1)
original = re.sub(
	r'\t// Rotation amounts for the right line.*?\];\n',
	'', original, flags=re.DOTALL, count=1)

# 2. Replace the instance ProcessBlock
old_instance = re.search(
	r'\t\[MethodImpl\(MethodImplOptions\.AggressiveOptimization\)\]\n'
	r'\tprivate void ProcessBlock\(ReadOnlySpan<byte> block\) \{.*?'
	r'\t\t_state\[0\] = t;\n\t\}',
	original, re.DOTALL)

if not old_instance:
	raise RuntimeError("Could not find instance ProcessBlock")

original = original[:old_instance.start()] + instance_method + original[old_instance.end():]

# 3. Remove old RotateLeft and F0-F3 from Ripemd128Digest class
original = re.sub(
	r'\n\t// ========== RIPEMD Boolean Functions ==========\n'
	r'.*?'
	r'\tprivate static uint F3\(uint x, uint y, uint z\) => \(x & z\) \| \(y & ~z\);\n',
	'\n', original, flags=re.DOTALL, count=1)

# 4. Replace static ProcessBlockStatic in the factory
old_static = re.search(
	r'\t\[MethodImpl\(MethodImplOptions\.AggressiveInlining\)\]\n'
	r'\tprivate static void ProcessBlockStatic\(ReadOnlySpan<byte> block, Span<uint> state\) \{.*?'
	r'\t\tstate\[0\] = t;\n\t\}',
	original, re.DOTALL)

if not old_static:
	raise RuntimeError("Could not find static ProcessBlockStatic")

original = original[:old_static.start()] + static_method + original[old_static.end():]

# 5. Remove old RotL from factory
original = re.sub(
	r'\n\t\[MethodImpl\(MethodImplOptions\.AggressiveInlining\)\]\n'
	r'\tprivate static uint RotL\(uint value, int bits\) => \(value << bits\) \| \(value >> \(32 - bits\)\);\n',
	'\n', original, flags=re.DOTALL, count=1)

# 6. Add SkipLocalsInit using if not present
if "using System.Runtime.CompilerServices;" not in original:
	# It's in global usings, should be fine
	pass

# Write output
with open(RIPEMD128_PATH, "w", encoding="utf-8-sig", newline="\r\n") as f:
	f.write(original)

# Count steps
step_count = original.count("uint.RotateLeft(a")
print(f"Patched Ripemd128.cs: {step_count} unrolled rotate steps")
print(f"File size: {len(original)} bytes")
