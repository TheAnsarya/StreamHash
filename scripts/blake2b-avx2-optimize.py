#!/usr/bin/env python3
"""Replace CompressAvx2 method in Blake2b.cs with vector-based message loading."""

import re

BLAKE2B_PATH = r"src\StreamHash.Core\Blake2b.cs"

with open(BLAKE2B_PATH, "r", encoding="utf-8-sig") as f:
    content = f.read()

# Find the CompressAvx2 method boundaries
# Start: the [MethodImpl...] attribute before CompressAvx2
# End: the closing brace before the G method comment
start_marker = "private void CompressAvx2(ReadOnlySpan<byte> block, bool isFinal) {"
start_idx = content.index(start_marker)
# Find the closing brace of CompressAvx2 — it's the "}\n" before "/// <summary>\n/// BLAKE2b G mixing function"
g_comment_idx = content.index("/// BLAKE2b G mixing function", start_idx)
# Walk backward to find "}\n"
method_end = content.rindex("}\n", start_idx, g_comment_idx) + len("}")

# Construct the new method body
# Using raw string to preserve exact formatting
NEW_METHOD = r"""private void CompressAvx2(ReadOnlySpan<byte> block, bool isFinal) {
	// Load message block as 4 vectors — all-SIMD, eliminates 16 scalar→SIMD cross-domain moves
	// msg0=[w0,w1,w2,w3], msg1=[w4,w5,w6,w7], msg2=[w8,w9,w10,w11], msg3=[w12,w13,w14,w15]
	ref byte blockRef = ref MemoryMarshal.GetReference(block);
	var msg0 = Unsafe.As<byte, Vector256<ulong>>(ref blockRef);
	var msg1 = Unsafe.As<byte, Vector256<ulong>>(ref Unsafe.Add(ref blockRef, 32));
	var msg2 = Unsafe.As<byte, Vector256<ulong>>(ref Unsafe.Add(ref blockRef, 64));
	var msg3 = Unsafe.As<byte, Vector256<ulong>>(ref Unsafe.Add(ref blockRef, 96));

	// Load rotation masks from static fields
	var rot24Mask = Rot24Mask;
	var rot16Mask = Rot16Mask;

	// Initialize working vector rows from hash state and IV using direct vector loads
	ref ulong hRef = ref MemoryMarshal.GetArrayDataReference(_h);
	var row0 = Unsafe.As<ulong, Vector256<ulong>>(ref hRef);
	var row1 = Unsafe.As<ulong, Vector256<ulong>>(ref Unsafe.Add(ref hRef, 4));
	ref ulong ivRef = ref MemoryMarshal.GetArrayDataReference(IV);
	var row2 = Unsafe.As<ulong, Vector256<ulong>>(ref ivRef);
	var row3 = Avx2.Xor(
		Unsafe.As<ulong, Vector256<ulong>>(ref Unsafe.Add(ref ivRef, 4)),
		Vector256.Create(_t0, _t1, isFinal ? 0xffffffffffffffff : 0UL, 0UL));

	Vector256<ulong> b0, b1, t0, t1;

		// ===== Round 0 (sigma: 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15) =====
		// Column: b0=[w0,w2,w4,w6], b1=[w1,w3,w5,w7]
		b0 = Avx2.Permute4x64(Avx2.UnpackLow(msg0, msg1), 0xD8);
		b1 = Avx2.Permute4x64(Avx2.UnpackHigh(msg0, msg1), 0xD8);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w8,w10,w12,w14], b1=[w9,w11,w13,w15]
		b0 = Avx2.Permute4x64(Avx2.UnpackLow(msg2, msg3), 0xD8);
		b1 = Avx2.Permute4x64(Avx2.UnpackHigh(msg2, msg3), 0xD8);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 1 (sigma: 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3) =====
		// Column: b0=[w14,w4,w9,w13], b1=[w10,w8,w15,w6]
		t0 = Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64();
		t1 = Avx2.UnpackHigh(msg2, msg3);
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x06), t1, 0x20);
		t0 = Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x30).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(msg2, 0x02), Avx2.Permute4x64(t0, 0x0B), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w1,w0,w11,w5], b1=[w12,w2,w7,w3]
		t0 = Avx2.Blend(msg2.AsInt32(), msg1.AsInt32(), 0x0C).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(msg0, 0x01), Avx2.Permute4x64(t0, 0x0D), 0x20);
		t0 = Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0x30).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x02), Avx2.UnpackHigh(msg1, msg0), 0x31);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 2 (sigma: 11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4) =====
		// Column: b0=[w11,w12,w5,w15], b1=[w8,w0,w2,w13]
		t0 = Avx2.Blend(msg2.AsInt32(), msg3.AsInt32(), 0x03).AsUInt64();
		t1 = Avx2.Permute4x64(Avx2.UnpackHigh(msg1, msg3), 0x03);
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x0C), t1, 0x20);
		t0 = Avx2.Blend(msg0.AsInt32(), msg3.AsInt32(), 0x0C).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.UnpackLow(msg2, msg0), Avx2.Permute4x64(t0, 0x09), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w10,w3,w7,w9], b1=[w14,w6,w1,w4]
		t0 = Avx2.Blend(msg2.AsInt32(), msg0.AsInt32(), 0xC0).AsUInt64();
		t1 = Avx2.Blend(msg1.AsInt32(), msg2.AsInt32(), 0x0C).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x0B), Avx2.Permute4x64(t1, 0x0D), 0x20);
		t0 = Avx2.Permute4x64(Avx2.UnpackLow(msg3, msg1), 0x0B);
		t1 = Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64();
		b1 = Avx2.Permute2x128(t0, Avx2.Permute4x64(t1, 0x01), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 3 (sigma: 7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8) =====
		// Column: b0=[w7,w3,w13,w11], b1=[w9,w1,w12,w14]
		t0 = Avx2.Permute4x64(Avx2.UnpackHigh(msg1, msg0), 0x0B);
		t1 = Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0xC0).AsUInt64();
		b0 = Avx2.Permute2x128(t0, Avx2.Permute4x64(t1, 0x07), 0x20);
		b1 = Avx2.Permute2x128(Avx2.UnpackHigh(msg2, msg0), Avx2.Permute4x64(msg3, 0x08), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w2,w5,w4,w15], b1=[w6,w10,w0,w8]
		t0 = Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0x0C).AsUInt64();
		t1 = Avx2.Blend(msg1.AsInt32(), msg3.AsInt32(), 0xC0).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x09), Avx2.Permute4x64(t1, 0x0C), 0x20);
		t0 = Avx2.Permute4x64(Avx2.UnpackLow(msg1, msg2), 0x0B);
		b1 = Avx2.Permute2x128(t0, Avx2.UnpackLow(msg0, msg2), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 4 (sigma: 9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13) =====
		// Column: b0=[w9,w5,w2,w10], b1=[w0,w7,w4,w15]
		b0 = Avx2.Permute2x128(Avx2.UnpackHigh(msg2, msg1), Avx2.UnpackLow(msg0, msg2), 0x30);
		t0 = Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0xC0).AsUInt64();
		t1 = Avx2.Blend(msg1.AsInt32(), msg3.AsInt32(), 0xC0).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x0C), Avx2.Permute4x64(t1, 0x0C), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w14,w11,w6,w3], b1=[w1,w12,w8,w13]
		t0 = Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0xC0).AsUInt64();
		t1 = Avx2.Blend(msg1.AsInt32(), msg0.AsInt32(), 0xC0).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x0B), Avx2.Permute4x64(t1, 0x0B), 0x20);
		t0 = Avx2.Blend(msg0.AsInt32(), msg3.AsInt32(), 0x03).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x04), Avx2.Blend(msg2.AsInt32(), msg3.AsInt32(), 0x0C).AsUInt64(), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 5 (sigma: 2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9) =====
		// Column: b0=[w2,w6,w0,w8], b1=[w12,w10,w11,w3]
		t0 = Avx2.Permute4x64(Avx2.UnpackLow(msg0, msg1), 0x0B);
		b0 = Avx2.Permute2x128(t0, Avx2.UnpackLow(msg0, msg2), 0x20);
		t0 = Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x30).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x08), Avx2.UnpackHigh(msg2, msg0), 0x31);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w4,w7,w15,w1], b1=[w13,w5,w14,w9]
		t0 = Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0x0C).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(msg1, 0x0C), Avx2.Permute4x64(t0, 0x0D), 0x20);
		t0 = Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x0C).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.UnpackHigh(msg3, msg1), Avx2.Permute4x64(t0, 0x09), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 6 (sigma: 12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11) =====
		// Column: b0=[w12,w1,w14,w4], b1=[w5,w15,w13,w10]
		t0 = Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0x0C).AsUInt64();
		t1 = Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64();
		b0 = Avx2.Permute2x128(t0, Avx2.Permute4x64(t1, 0x08), 0x20);
		t0 = Avx2.Permute4x64(Avx2.UnpackHigh(msg1, msg3), 0x03);
		t1 = Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x30).AsUInt64();
		b1 = Avx2.Permute2x128(t0, Avx2.Permute4x64(t1, 0x06), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w0,w6,w9,w8], b1=[w7,w3,w2,w11]
		t0 = Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0x30).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x08), Avx2.Permute4x64(msg2, 0x04), 0x20);
		t0 = Avx2.Permute4x64(Avx2.UnpackHigh(msg1, msg0), 0x0B);
		t1 = Avx2.Blend(msg0.AsInt32(), msg2.AsInt32(), 0xC0).AsUInt64();
		b1 = Avx2.Permute2x128(t0, Avx2.Permute4x64(t1, 0x0B), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 7 (sigma: 13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10) =====
		// Column: b0=[w13,w7,w12,w3], b1=[w11,w14,w1,w9]
		t0 = Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0xC0).AsUInt64();
		t1 = Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0xC0).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x07), Avx2.Permute4x64(t1, 0x0C), 0x20);
		t0 = Avx2.Blend(msg2.AsInt32(), msg3.AsInt32(), 0x30).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x0E), Avx2.UnpackHigh(msg0, msg2), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w5,w15,w8,w2], b1=[w0,w4,w6,w10]
		t0 = Avx2.Permute4x64(Avx2.UnpackHigh(msg1, msg3), 0x03);
		t1 = Avx2.Blend(msg2.AsInt32(), msg0.AsInt32(), 0x30).AsUInt64();
		b0 = Avx2.Permute2x128(t0, Avx2.Permute4x64(t1, 0x08), 0x20);
		b1 = Avx2.Permute2x128(Avx2.UnpackLow(msg0, msg1), Avx2.UnpackLow(msg1, msg2), 0x30);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 8 (sigma: 6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5) =====
		// Column: b0=[w6,w14,w11,w0], b1=[w15,w9,w3,w8]
		t0 = Avx2.Permute4x64(Avx2.UnpackLow(msg1, msg3), 0x0B);
		t1 = Avx2.Blend(msg2.AsInt32(), msg0.AsInt32(), 0x03).AsUInt64();
		b0 = Avx2.Permute2x128(t0, Avx2.Permute4x64(t1, 0x0C), 0x20);
		t0 = Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x0C).AsUInt64();
		t1 = Avx2.Blend(msg0.AsInt32(), msg2.AsInt32(), 0x03).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x0D), Avx2.Permute4x64(t1, 0x0C), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w12,w13,w1,w10], b1=[w2,w7,w4,w5]
		t0 = Avx2.Blend(msg0.AsInt32(), msg2.AsInt32(), 0x30).AsUInt64();
		b0 = Avx2.Permute2x128(msg3, Avx2.Permute4x64(t0, 0x06), 0x20);
		t0 = Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0xC0).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x0B), msg1, 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 9 (sigma: 10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0) =====
		// Column: b0=[w10,w8,w7,w1], b1=[w2,w4,w6,w5]
		t0 = Avx2.Blend(msg1.AsInt32(), msg0.AsInt32(), 0x0C).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(msg2, 0x02), Avx2.Permute4x64(t0, 0x0D), 0x20);
		t0 = Avx2.Blend(msg0.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x08), Avx2.Permute4x64(msg1, 0x09), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Diagonalize
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		// Diagonal: b0=[w15,w9,w3,w12], b1=[w11,w14,w13,w0]
		t0 = Avx2.Blend(msg3.AsInt32(), msg2.AsInt32(), 0x0C).AsUInt64();
		t1 = Avx2.Blend(msg0.AsInt32(), msg3.AsInt32(), 0x03).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x0D), Avx2.Permute4x64(t1, 0x0C), 0x20);
		t0 = Avx2.Blend(msg2.AsInt32(), msg3.AsInt32(), 0x30).AsUInt64();
		t1 = Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0x03).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x0E), Avx2.Permute4x64(t1, 0x04), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		// Undiagonalize
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 10 (same as Round 0) =====
		b0 = Avx2.Permute4x64(Avx2.UnpackLow(msg0, msg1), 0xD8);
		b1 = Avx2.Permute4x64(Avx2.UnpackHigh(msg0, msg1), 0xD8);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		b0 = Avx2.Permute4x64(Avx2.UnpackLow(msg2, msg3), 0xD8);
		b1 = Avx2.Permute4x64(Avx2.UnpackHigh(msg2, msg3), 0xD8);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

		// ===== Round 11 (same as Round 1) =====
		t0 = Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x03).AsUInt64();
		t1 = Avx2.UnpackHigh(msg2, msg3);
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x06), t1, 0x20);
		t0 = Avx2.Blend(msg3.AsInt32(), msg1.AsInt32(), 0x30).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(msg2, 0x02), Avx2.Permute4x64(t0, 0x0B), 0x20);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		row1 = Avx2.Permute4x64(row1, 0x39);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x93);
		t0 = Avx2.Blend(msg2.AsInt32(), msg1.AsInt32(), 0x0C).AsUInt64();
		b0 = Avx2.Permute2x128(Avx2.Permute4x64(msg0, 0x01), Avx2.Permute4x64(t0, 0x0D), 0x20);
		t0 = Avx2.Blend(msg3.AsInt32(), msg0.AsInt32(), 0x30).AsUInt64();
		b1 = Avx2.Permute2x128(Avx2.Permute4x64(t0, 0x02), Avx2.UnpackHigh(msg1, msg0), 0x31);
		row0 = Avx2.Add(Avx2.Add(row0, row1), b0);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsUInt32(), 0xB1).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		row1 = Avx2.Shuffle(Avx2.Xor(row1, row2).AsByte(), rot24Mask).AsUInt64();
		row0 = Avx2.Add(Avx2.Add(row0, row1), b1);
		row3 = Avx2.Shuffle(Avx2.Xor(row3, row0).AsByte(), rot16Mask).AsUInt64();
		row2 = Avx2.Add(row2, row3);
		t0 = Avx2.Xor(row1, row2);
		row1 = Avx2.Or(Avx2.ShiftRightLogical(t0, 63), Avx2.ShiftLeftLogical(t0, 1));
		row1 = Avx2.Permute4x64(row1, 0x93);
		row2 = Avx2.Permute4x64(row2, 0x4E);
		row3 = Avx2.Permute4x64(row3, 0x39);

	// Finalize: XOR upper and lower halves back into state using vector operations
	var f0 = Avx2.Xor(row0, row2);
	var f1 = Avx2.Xor(row1, row3);
	ref ulong hEnd = ref MemoryMarshal.GetArrayDataReference(_h);
	Unsafe.As<ulong, Vector256<ulong>>(ref hEnd) = Avx2.Xor(
		Unsafe.As<ulong, Vector256<ulong>>(ref hEnd), f0);
	Unsafe.As<ulong, Vector256<ulong>>(ref Unsafe.Add(ref hEnd, 4)) = Avx2.Xor(
		Unsafe.As<ulong, Vector256<ulong>>(ref Unsafe.Add(ref hEnd, 4)), f1);
	}"""

# Replace the method body
new_content = content[:start_idx] + NEW_METHOD + content[method_end:]

with open(BLAKE2B_PATH, "w", encoding="utf-8-sig", newline="\r\n") as f:
    f.write(new_content)

print(f"Replaced CompressAvx2 method ({method_end - start_idx} chars old → {len(NEW_METHOD)} chars new)")
