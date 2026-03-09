using System.Text.Json;

namespace StreamHash.Core.Tests;

/// <summary>
/// Golden reference tests for regression detection.
/// Verifies that all 70 hash algorithm outputs remain stable across code changes.
/// Uses snapshot pattern: generates golden file on first run, verifies on subsequent runs.
/// </summary>
public class GoldenReferenceTests {
	private static readonly byte[] AbcData = "abc"u8.ToArray();
	private static readonly byte[] EmptyData = [];
	private static readonly byte[] HelloWorldData = "Hello, World!"u8.ToArray();

	private static readonly string GoldenDir = Path.Combine(
		AppContext.BaseDirectory, "..", "..", "..", "ReferenceData");

	private static readonly JsonSerializerOptions JsonOptions = new() {
		WriteIndented = true,
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
	};

	private static SortedDictionary<string, string> ComputeAllHashes(byte[] data) {
		var results = new SortedDictionary<string, string>(StringComparer.Ordinal);
		foreach (var algo in Enum.GetValues<HashAlgorithm>()) {
			results[algo.ToString()] = HashFacade.ComputeHashHex(algo, data);
		}
		return results;
	}

	private static SortedDictionary<string, string>? LoadGolden(string path) {
		if (!File.Exists(path)) {
			return null;
		}
		return JsonSerializer.Deserialize<SortedDictionary<string, string>>(File.ReadAllText(path), JsonOptions);
	}

	private static void SaveGolden(string path, SortedDictionary<string, string> hashes) {
		Directory.CreateDirectory(Path.GetDirectoryName(path)!);
		File.WriteAllText(path, JsonSerializer.Serialize(hashes, JsonOptions));
	}

	private static void VerifyAgainstGolden(string goldenPath, byte[] data) {
		var current = ComputeAllHashes(data);

		var golden = LoadGolden(goldenPath);
		if (golden is null) {
			SaveGolden(goldenPath, current);
			golden = current;
		}

		foreach (var (algo, expectedHash) in golden) {
			current.Should().ContainKey(algo,
				$"golden reference contains algorithm '{algo}' but current code does not");
			current[algo].Should().Be(expectedHash,
				$"algorithm {algo} hash changed from golden reference");
		}

		current.Should().HaveCount(golden.Count, "algorithm count changed from golden reference");
	}

	[Fact]
	public void AllAlgorithms_EmptyInput_MatchGoldenReference() {
		VerifyAgainstGolden(Path.Combine(GoldenDir, "golden-empty.json"), EmptyData);
	}

	[Fact]
	public void AllAlgorithms_AbcInput_MatchGoldenReference() {
		VerifyAgainstGolden(Path.Combine(GoldenDir, "golden-abc.json"), AbcData);
	}

	[Fact]
	public void AllAlgorithms_HelloWorldInput_MatchGoldenReference() {
		VerifyAgainstGolden(Path.Combine(GoldenDir, "golden-hello-world.json"), HelloWorldData);
	}

	[Fact]
	public void AllAlgorithms_AbcInput_ProduceLowercaseHex() {
		var hashes = ComputeAllHashes(AbcData);
		foreach (var (algo, hash) in hashes) {
			hash.Should().MatchRegex("^[0-9a-f]+$",
				$"{algo} should produce lowercase hex output");
		}
	}

	[Fact]
	public void AllAlgorithms_Count_Is70() {
		var hashes = ComputeAllHashes(AbcData);
		hashes.Should().HaveCount(70, "StreamHash should support exactly 70 algorithms");
	}
}
