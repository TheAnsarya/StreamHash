using System.Runtime.Intrinsics.X86;

namespace StreamHash.Core;

/// <summary>
/// Streaming implementation of CRC-16 with multiple polynomial variants.
/// </summary>
/// <remarks>
/// <para>
/// CRC-16 (Cyclic Redundancy Check - 16 bit) is a widely used checksum algorithm
/// that produces a 16-bit hash value. Different applications use different polynomials.
/// </para>
/// <para>
/// <b>Supported Variants:</b>
/// <list type="bullet">
/// <item><b>CCITT:</b> Polynomial 0x1021, used in X.25, HDLC, Bluetooth</item>
/// <item><b>ARC:</b> Polynomial 0x8005, used in LHA, ZOO</item>
/// <item><b>MODBUS:</b> Polynomial 0x8005 with different init/reflect</item>
/// <item><b>USB:</b> Same as ARC but with 0xFFFF init</item>
/// <item><b>XMODEM:</b> Polynomial 0x1021 with 0x0000 init</item>
/// <item><b>KERMIT:</b> Polynomial 0x1021, reflected, also called CCITT-FALSE</item>
/// <item><b>DNP:</b> Polynomial 0x3D65, used in DNP3 protocol</item>
/// <item><b>MAXIM:</b> Polynomial 0x8005, reflected with 0x0000 init</item>
/// </list>
/// </para>
/// <para>
/// <b>Algorithm:</b>
/// <list type="number">
/// <item>Initialize CRC register with initial value</item>
/// <item>For each byte, XOR with CRC and lookup in precomputed table</item>
/// <item>Optionally apply final XOR mask</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Default CRC-16-CCITT
/// using var crc = new Crc16Streaming();
/// crc.Update(data);
/// ushort result = crc.Finalize();
///
/// // CRC-16-MODBUS
/// using var crcModbus = new Crc16Streaming(Crc16Variant.Modbus);
/// crcModbus.Update(data);
/// ushort modbusResult = crcModbus.Finalize();
/// </code>
/// </example>
public sealed class Crc16Streaming : IStreamingHash<ushort> {
	// ═══════════════════════════════════════════════════════════════════════════
	// SIMD Feature Detection
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Indicates whether PCLMULQDQ instruction is available for hardware CRC acceleration.
	/// </summary>
	/// <remarks>
	/// CRC-16 can be accelerated using PCLMULQDQ (carry-less multiplication).
	/// This implementation uses table-based lookup but documents SIMD availability.
	/// </remarks>
	public static bool IsPclmulqdqSupported { get; } = Pclmulqdq.IsSupported;

	/// <summary>
	/// Indicates whether SSE4.1 SIMD instructions are available.
	/// </summary>
	public static bool IsSse41Supported { get; } = Sse41.IsSupported;

	// ═══════════════════════════════════════════════════════════════════════════
	// Constants and Lookup Tables
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Precomputed lookup table for CRC-16-CCITT polynomial (0x1021).
	/// Used for non-reflected variants (CCITT, XMODEM).
	/// </summary>
	private static readonly ushort[] CcittTable = GenerateTable(0x1021, false);

	/// <summary>
	/// Precomputed lookup table for CRC-16-CCITT polynomial (0x1021), reflected.
	/// Used for reflected variants (KERMIT).
	/// </summary>
	private static readonly ushort[] CcittTableReflected = GenerateTable(0x1021, true);

	/// <summary>
	/// Precomputed lookup table for CRC-16-ARC polynomial (0x8005), reflected.
	/// Used for ARC, MODBUS, USB, MAXIM variants.
	/// </summary>
	private static readonly ushort[] ArcTableReflected = GenerateTable(0x8005, true);

	/// <summary>
	/// Precomputed lookup table for CRC-16-DNP polynomial (0x3D65), reflected.
	/// </summary>
	private static readonly ushort[] DnpTableReflected = GenerateTable(0x3d65, true);

	// ═══════════════════════════════════════════════════════════════════════════
	// Instance State
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>The variant configuration.</summary>
	private readonly Crc16VariantConfig _config;

	/// <summary>The lookup table for this variant.</summary>
	private readonly ushort[] _table;

	/// <summary>Current CRC value.</summary>
	private ushort _crc;

	/// <summary>Total bytes processed.</summary>
	private long _totalBytes;

	/// <summary>Whether Finalize has been called.</summary>
	private bool _finalized;

	/// <summary>Whether the instance has been disposed.</summary>
	private bool _disposed;

	// ═══════════════════════════════════════════════════════════════════════════
	// Properties
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	public int BlockSize => 1;

	/// <inheritdoc/>
	public int DigestSize => 2;

	/// <inheritdoc/>
	public long TotalBytesProcessed => _totalBytes;

	/// <summary>
	/// Gets the CRC-16 variant being used.
	/// </summary>
	public Crc16Variant Variant { get; }

	// ═══════════════════════════════════════════════════════════════════════════
	// Constructors
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Creates a new CRC-16 hasher with the CCITT variant (default).
	/// </summary>
	public Crc16Streaming() : this(Crc16Variant.Ccitt) { }

	/// <summary>
	/// Creates a new CRC-16 hasher with the specified variant.
	/// </summary>
	/// <param name="variant">The CRC-16 variant to use.</param>
	public Crc16Streaming(Crc16Variant variant) {
		Variant = variant;
		_config = GetVariantConfig(variant);
		_table = GetTableForVariant(variant);
		_crc = _config.Init;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Update Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> data) {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) {
			throw new InvalidOperationException("Cannot update after Finalize(). Call Reset() first.");
		}

		if (_config.RefIn) {
			// Reflected input: process LSB first
			foreach (byte b in data) {
				_crc = (ushort)((_crc >> 8) ^ _table[(_crc ^ b) & 0xff]);
			}
		} else {
			// Non-reflected input: process MSB first
			foreach (byte b in data) {
				_crc = (ushort)((_crc << 8) ^ _table[((_crc >> 8) ^ b) & 0xff]);
			}
		}

		_totalBytes += data.Length;
	}

	/// <inheritdoc/>
	public void Update(byte[] data, int offset, int length) {
		ArgumentNullException.ThrowIfNull(data);
		Update(data.AsSpan(offset, length));
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Finalization
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	public ushort Finalize() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		if (_finalized) {
			throw new InvalidOperationException("Finalize() already called. Call Reset() first.");
		}

		_finalized = true;
		ushort result = _crc;

		// Apply output reflection if needed (and input wasn't already reflected)
		if (_config.RefOut && !_config.RefIn) {
			result = ReflectBits(result, 16);
		} else if (!_config.RefOut && _config.RefIn) {
			result = ReflectBits(result, 16);
		}

		// Apply final XOR
		result ^= _config.XorOut;
		return result;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Reset and Dispose
	// ═══════════════════════════════════════════════════════════════════════════

	/// <inheritdoc/>
	public void Reset() {
		ObjectDisposedException.ThrowIf(_disposed, this);
		_crc = _config.Init;
		_totalBytes = 0;
		_finalized = false;
	}

	/// <inheritdoc/>
	public void Dispose() {
		_disposed = true;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Static Hash Methods
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Computes CRC-16 of data in one call.
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="variant">The CRC-16 variant (default: CCITT).</param>
	/// <returns>The 16-bit CRC value.</returns>
	public static ushort Hash(ReadOnlySpan<byte> data, Crc16Variant variant = Crc16Variant.Ccitt) {
		using var hasher = new Crc16Streaming(variant);
		hasher.Update(data);
		return hasher.Finalize();
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Table Generation
	// ═══════════════════════════════════════════════════════════════════════════

	/// <summary>
	/// Generates a CRC-16 lookup table for the specified polynomial.
	/// </summary>
	/// <param name="polynomial">The polynomial to use.</param>
	/// <param name="reflected">Whether to generate a reflected table.</param>
	/// <returns>256-entry lookup table.</returns>
	private static ushort[] GenerateTable(ushort polynomial, bool reflected) {
		var table = new ushort[256];

		if (reflected) {
			ushort reflectedPoly = ReflectBits(polynomial, 16);
			for (int i = 0; i < 256; i++) {
				ushort crc = (ushort)i;
				for (int j = 0; j < 8; j++) {
					if ((crc & 1) != 0) {
						crc = (ushort)((crc >> 1) ^ reflectedPoly);
					} else {
						crc >>= 1;
					}
				}
				table[i] = crc;
			}
		} else {
			for (int i = 0; i < 256; i++) {
				ushort crc = (ushort)(i << 8);
				for (int j = 0; j < 8; j++) {
					if ((crc & 0x8000) != 0) {
						crc = (ushort)((crc << 1) ^ polynomial);
					} else {
						crc <<= 1;
					}
				}
				table[i] = crc;
			}
		}

		return table;
	}

	/// <summary>
	/// Reflects (reverses) the bits in a value.
	/// </summary>
	private static ushort ReflectBits(ushort value, int bits) {
		ushort result = 0;
		for (int i = 0; i < bits; i++) {
			if ((value & (1 << i)) != 0) {
				result |= (ushort)(1 << (bits - 1 - i));
			}
		}
		return result;
	}

	/// <summary>
	/// Gets the lookup table for a variant.
	/// </summary>
	private static ushort[] GetTableForVariant(Crc16Variant variant) => variant switch {
		Crc16Variant.Ccitt => CcittTable,
		Crc16Variant.Xmodem => CcittTable,
		Crc16Variant.Kermit => CcittTableReflected,
		Crc16Variant.Arc => ArcTableReflected,
		Crc16Variant.Modbus => ArcTableReflected,
		Crc16Variant.Usb => ArcTableReflected,
		Crc16Variant.Maxim => ArcTableReflected,
		Crc16Variant.Dnp => DnpTableReflected,
		_ => CcittTable
	};

	/// <summary>
	/// Gets the configuration for a variant.
	/// </summary>
	private static Crc16VariantConfig GetVariantConfig(Crc16Variant variant) => variant switch {
		Crc16Variant.Ccitt => new Crc16VariantConfig(0xffff, 0x0000, false, false),
		Crc16Variant.Xmodem => new Crc16VariantConfig(0x0000, 0x0000, false, false),
		Crc16Variant.Kermit => new Crc16VariantConfig(0x0000, 0x0000, true, true),
		Crc16Variant.Arc => new Crc16VariantConfig(0x0000, 0x0000, true, true),
		Crc16Variant.Modbus => new Crc16VariantConfig(0xffff, 0x0000, true, true),
		Crc16Variant.Usb => new Crc16VariantConfig(0xffff, 0xffff, true, true),
		Crc16Variant.Maxim => new Crc16VariantConfig(0x0000, 0xffff, true, true),
		Crc16Variant.Dnp => new Crc16VariantConfig(0x0000, 0xffff, true, true),
		_ => new Crc16VariantConfig(0xffff, 0x0000, false, false)
	};

	/// <summary>
	/// Configuration for a CRC-16 variant.
	/// </summary>
	private readonly record struct Crc16VariantConfig(ushort Init, ushort XorOut, bool RefIn, bool RefOut);
}

/// <summary>
/// CRC-16 polynomial variants.
/// </summary>
public enum Crc16Variant {
	/// <summary>CRC-16-CCITT: Poly=0x1021, Init=0xFFFF, RefIn=false, RefOut=false, XorOut=0x0000</summary>
	Ccitt,

	/// <summary>CRC-16-XMODEM: Poly=0x1021, Init=0x0000, RefIn=false, RefOut=false, XorOut=0x0000</summary>
	Xmodem,

	/// <summary>CRC-16-KERMIT: Poly=0x1021, Init=0x0000, RefIn=true, RefOut=true, XorOut=0x0000</summary>
	Kermit,

	/// <summary>CRC-16-ARC: Poly=0x8005, Init=0x0000, RefIn=true, RefOut=true, XorOut=0x0000</summary>
	Arc,

	/// <summary>CRC-16-MODBUS: Poly=0x8005, Init=0xFFFF, RefIn=true, RefOut=true, XorOut=0x0000</summary>
	Modbus,

	/// <summary>CRC-16-USB: Poly=0x8005, Init=0xFFFF, RefIn=true, RefOut=true, XorOut=0xFFFF</summary>
	Usb,

	/// <summary>CRC-16-MAXIM: Poly=0x8005, Init=0x0000, RefIn=true, RefOut=true, XorOut=0xFFFF</summary>
	Maxim,

	/// <summary>CRC-16-DNP: Poly=0x3D65, Init=0x0000, RefIn=true, RefOut=true, XorOut=0xFFFF</summary>
	Dnp,
}
