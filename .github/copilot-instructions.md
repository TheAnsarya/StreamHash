# StreamHash - AI Copilot Directives

## Project Overview

**StreamHash** is a high-performance, memory-efficient streaming hash library for .NET 10+. It provides incremental/streaming implementations of hash algorithms that traditionally require full data in memory.

**Home Folder:** `C:\Users\me\source\repos\StreamHash`

## ⚠️ CRITICAL: Always Use Latest Modern Versions

**ALWAYS use the most modern, latest versions of everything:**

- **.NET 10** (not .NET 9, 8, 7, or older)
- **C# 14** (latest language version)
- **Visual Studio 2026** (if applicable)
- **Latest NuGet packages** - Always check for and use newest stable versions

## Core Mission

Convert non-streaming hash algorithms to streaming implementations:
1. **MurmurHash3** (32-bit and 128-bit variants)
2. **CityHash** (64-bit and 128-bit variants)
3. **SpookyHash V2** (128-bit)
4. **SipHash** (2-4 variant, 64-bit)
5. **FarmHash** (64-bit)
6. **HighwayHash** (64-bit)

## Architecture

### Solution Structure
```
StreamHash/
├── src/
│   ├── StreamHash.Core/           # Core streaming hash implementations
│   │   ├── Abstractions/          # Interfaces and base classes
│   │   ├── MurmurHash/            # MurmurHash3 streaming implementation
│   │   ├── CityHash/              # CityHash streaming implementation
│   │   ├── SpookyHash/            # SpookyHash streaming implementation
│   │   ├── SipHash/               # SipHash streaming implementation
│   │   ├── FarmHash/              # FarmHash streaming implementation
│   │   └── HighwayHash/           # HighwayHash streaming implementation
│   └── StreamHash.Cli/            # CLI tool for testing/benchmarking
├── tests/
│   ├── StreamHash.Core.Tests/     # Unit tests
│   └── StreamHash.Integration.Tests/
├── benchmarks/
│   └── StreamHash.Benchmarks/     # BenchmarkDotNet performance tests
├── docs/                          # User documentation
│   ├── algorithms/                # Algorithm-specific documentation
│   ├── api/                       # API reference
│   └── guides/                    # Usage guides
├── ~docs/                         # Development documentation
│   ├── chat-logs/                 # AI conversation logs
│   ├── session-logs/              # Session summaries
│   ├── plans/                     # Planning documents
│   └── roadmaps/                  # Feature roadmaps
└── samples/                       # Usage samples
```

## Coding Standards

### Indentation
- **ALWAYS use TABS, never spaces** - Enforced by `.editorconfig`
- Tab width: 4 spaces equivalent
- Applies to ALL files: C#, JSON, Markdown, YAML, etc.

### Brace Style
- **K&R style** - Opening braces on SAME line, not new line
```csharp
if (condition) {
	// code
} else {
	// code
}
```

### Hexadecimal Values
- **Always lowercase** for hex values
- Correct: `0xca6e`, `0xff00`
- Incorrect: `0xCA6E`, `0xFF00`

### C# Conventions
- File-scoped namespaces: `namespace StreamHash.Core;`
- Modern C# 14 features: pattern matching, collection expressions, spans
- **XML documentation on ALL public AND private members**
- Inline comments for complex algorithms with reference links

### Documentation Requirements
- Every public type must have `<summary>` and `<remarks>`
- Every method must document parameters, return values, and exceptions
- Include `<example>` blocks for common usage patterns
- Reference original algorithm papers/implementations in `<seealso>`

## Algorithm Implementation Guidelines

### Streaming Interface
All streaming hash implementations must implement:
```csharp
public interface IStreamingHash<TResult> : IDisposable {
	void Update(ReadOnlySpan<byte> data);
	void Update(byte[] data, int offset, int length);
	TResult Finalize();
	void Reset();
	int BlockSize { get; }
	int DigestSize { get; }
}
```

### Memory Efficiency
- Use `Span<T>` and `ReadOnlySpan<T>` for all data operations
- Use `stackalloc` for small temporary buffers (< 1KB)
- Use `ArrayPool<T>` for larger temporary allocations
- Avoid allocations in hot paths

### SIMD Optimization
- Use `System.Runtime.Intrinsics` for SIMD operations
- Provide scalar fallbacks for all SIMD code
- Document which instruction sets are used (SSE2, AVX2, etc.)

## Git Workflow

### Commit Messages
Use conventional commits:
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation
- `test:` - Tests
- `perf:` - Performance
- `refactor:` - Refactoring

### Branching
- `main` - Stable releases
- `develop` - Integration branch
- `feature/*` - Feature branches
- `fix/*` - Bug fix branches

## Testing Requirements

- Minimum 95% code coverage
- Test vectors from original algorithm specifications
- Property-based tests for streaming consistency
- Benchmark comparisons against reference implementations

## Documentation Files

### `docs/`
- Algorithm descriptions with mathematical formulas
- API reference with examples
- Performance comparison charts

### `~docs/` (Development)
- Session logs: `~docs/session-logs/YYYY-MM-DD-session-NN.md`
- Chat logs: `~docs/chat-logs/YYYY-MM-DD-chat-NN.md`
- **NEVER edit** `~docs/streamhash-manual-prompts-log.txt`

## Licensing

**Always use `The Unlicense` for this project - we don't believe in copyright, code is code.**

Avoid obvious copyright issues if you can, only for legal reasons. The project owner doesn't give a shit about copyright.

Note: Some algorithm implementations reference other implementations. Document attributions in THIRD_PARTY_NOTICES.md for good faith, not legal requirement.

