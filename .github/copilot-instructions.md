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

## GitHub Issue Management

### ⚠️ CRITICAL: Always Create Issues on GitHub Directly

**NEVER just document issues in markdown files.** Always create actual GitHub issues using the `gh` CLI:

```powershell
# Create an issue
gh issue create --repo TheAnsarya/StreamHash --title "Issue Title" --body "Description" --label "label1,label2"

# Add labels
gh issue edit <number> --repo TheAnsarya/StreamHash --add-label "label"

# Close issue
gh issue close <number> --repo TheAnsarya/StreamHash --comment "Completed in commit abc123"
```

### Required Labels

- `performance` - Performance related
- `bug` - Bug fixes
- `enhancement` - New features
- `documentation` - Documentation updates
- `investigation` - Research/analysis tasks
- `high-priority`, `medium-priority`, `low-priority` - Priority levels
- `testing` - Test improvements
- `accuracy` - Hash accuracy related

### ⚠️ MANDATORY: Issue-First Workflow

**Always create GitHub issues BEFORE starting implementation work.** This is non-negotiable.

1. **Before Implementation:**
	- Create a GitHub issue describing the planned work
	- Include scope, approach, and acceptance criteria
	- Add appropriate labels

2. **During Implementation:**
	- Reference issue number in commits: `git commit -m "Fix streaming hash - #42"`
	- Update issue with progress comments if work spans multiple sessions
	- Add sub-issues for discovered work

3. **After Implementation:**
	- Close issue with completion comment including commit hash
	- Link related issues if applicable

### ⚠️ MANDATORY: Prompt Tracking for AI-Created Issues

When creating GitHub issues from AI prompts, **IMMEDIATELY** add the original user prompt as the **FIRST comment** right after creating the issue:

```powershell
# Create issue
$issueUrl = gh issue create --repo TheAnsarya/StreamHash --title "Description" --body "Details" --label "label"
$issueNum = ($issueUrl -split '/')[-1]

# IMMEDIATELY add prompt as first comment (before any other work)
gh issue comment $issueNum --repo TheAnsarya/StreamHash --body "Prompt for work:
<original user prompt that triggered this work>"
```

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

### File Formatting (CRITICAL)

**ALL files must follow these rules:**

- **Encoding:** UTF-8 with BOM
- **Line Endings:** CRLF (Windows style)
- **Indentation:** TABS only, NEVER spaces
- **Final Newline:** Always include a blank line at the end of every file
- **Trailing Whitespace:** Remove from all lines

**Markdown Files:**
- Format using `.editorconfig` rules
- Use markdownlint with **MD010 disabled** (hard tabs are REQUIRED, not forbidden)
- All markdown files must have proper heading hierarchy
- Include blank line at end of file

### ⚠️ MANDATORY: Fix Markdownlint Warnings

Always fix markdownlint warnings when creating or editing markdown files.

Minimum rules to enforce in every markdown update:

- **MD022** - Blank lines above and below headings
- **MD031** - Blank lines around fenced code blocks
- **MD032** - Blank lines around lists
- **MD047** - File ends with a single newline

Generate markdown content with proper spacing by default to avoid avoidable follow-up formatting edits.

### ⚠️ MANDATORY: Documentation Link-Tree

Every markdown or documentation file must be discoverable from `README.md` through a maintained link-tree.

- Update `README.md` when adding docs
- Update docs index pages when reorganizing docs
- Avoid orphan markdown files

**When creating or editing files:**
1. Always use tabs for indentation
2. Always add a blank line at the end
3. Always use UTF-8 encoding with BOM
4. Always use CRLF line endings
5. Never leave trailing whitespace

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

## Code Documentation Standards

### XML Documentation (xmldoc)
**Every type, method, property, and field must have XML documentation:**

```csharp
/// <summary>
/// Brief description of what this does.
/// </summary>
/// <remarks>
/// <para>
/// Additional details, usage notes, or implementation notes.
/// Use &lt;para&gt; tags for multiple paragraphs.
/// </para>
/// </remarks>
/// <param name="data">Description of the parameter.</param>
/// <returns>Description of return value.</returns>
/// <exception cref="ArgumentNullException">When data is null.</exception>
/// <example>
/// <code>
/// var result = MyMethod(data);
/// </code>
/// </example>
public string MyMethod(byte[] data) {
	// Implementation
}
```

**Indentation rules for xmldoc:**
- Use TABS for indentation inside xmldoc comments (not spaces)
- Align continuation lines with the content above
- Keep `<para>` content indented with tabs

### Inline Comments
**Add inline comments when:**
- Explaining a non-obvious algorithm or calculation
- Documenting magic numbers or constants
- Describing why code exists (not just what it does)
- Warning about edge cases or gotchas
- Referencing external specifications or papers

**Example:**
```csharp
// MurmurHash3 finalization mix - forces all bits to avalanche
// Reference: https://github.com/aappleby/smhasher/wiki/MurmurHash3
h ^= h >> 16;
h *= 0x85ebca6b;
h ^= h >> 13;
h *= 0xc2b2ae35;
h ^= h >> 16;
```

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

### ⚠️ ABSOLUTE RULE: Hash Accuracy is Sacred

**NEVER sacrifice hash correctness for performance.** This is the #1 non-negotiable rule.

- **Every performance optimization MUST be correctness-preserving** — if a change could alter hash output in any way, it is rejected
- **Run ALL tests after every change** — all xUnit tests must pass before any commit
- **Benchmark BEFORE and AFTER** — prove the improvement with data, not just theory
- **When in doubt, don't optimize** — a slower correct hasher is infinitely better than a faster broken one

#### Verification Checklist (for EVERY performance change):

1. All xUnit tests pass (`dotnet test`)
2. Benchmark shows measurable improvement (BenchmarkDotNet)
3. Change is semantics-preserving (same hash outputs)
4. No new warnings in build output
5. Test vectors still match reference implementations

#### Focused Validation Commands (Fletcher)

- Reference-equivalence tests:
	- `dotnet test tests/StreamHash.Core.Tests/StreamHash.Core.Tests.csproj -c Release --filter "ComputeFletcher16_MatchesReferenceImplementation|ComputeFletcher32_MatchesReferenceImplementation"`
- Fletcher benchmark coverage:
	- `dotnet run --project benchmarks/StreamHash.Benchmarks/StreamHash.Benchmarks.csproj -c Release -- --filter "*HashFacadeBenchmarks*Facade_Fletcher*" --job short`

#### Types of Safe Performance Changes:

- **Buffer size tuning** — different ArrayPool sizes for different file ranges
- **Avoiding copies** — use `Span<T>` instead of array copies
- **Eliminating allocations** — pool or reuse objects in hot paths
- **SIMD optimization** — vectorized implementations with scalar fallbacks
- **Inlining** — moving small hot-path methods for JIT optimization

#### Types of DANGEROUS Changes (require extra scrutiny):

- Anything touching hash algorithm core logic
- Buffer management changes that affect data fed to hash algorithms
- Reordering or parallelizing in ways that could skip bytes
- Byte order or endianness changes

## Problem-Solving Philosophy

### ⚠️ NEVER GIVE UP on Hard Problems

When a task is complex or seems difficult:

1. **NEVER declare something "too hard" or "not worth it"** and close the issue
2. **Break it down** — Create multiple smaller sub-issues for research, prototyping, and incremental progress
3. **Research first** — Create research issues to investigate approaches, alternatives, and prior art
4. **Document everything** — Create docs, code-plans, and analysis documents in `~docs/`
5. **Prototype** — Create spike/prototype branches to test approaches before committing
6. **Incremental progress** — Even partial progress is valuable
7. **Create issues for future work** — If something can't be done now, create well-documented issues with clear context for later

### What "Closing Too Soon" Looks Like

- "This is deeply integrated, keeping as-is" — Instead: break it into phases
- "Migration cost-prohibitive" — Instead: create research issues and prototype
- "High regression risk" — Instead: create test plan and incremental migration
- Close only when the work is **actually complete** or **truly impossible** (not just hard)

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

## ⚠️ CRITICAL: Versioning Policy

**DO NOT release a new NuGet package version without explicit user approval.**

### Version Number Rules
- **Patch (X.Y.Z)**: Increment for bug fixes, documentation updates, minor improvements
- **Minor (X.Y.0)**: Only increment when user explicitly requests
- **Major (X.0.0)**: NEVER increment unless user explicitly tells you to

### Release Process
1. Make changes and commit them
2. **WAIT** for user to say "release" or "publish"
3. Only then update version and push to NuGet

### Example
- Current: 1.6.0
- Bug fix: 1.6.1 (auto-increment patch OK if releasing)
- New feature: Still 1.6.1 unless user says "bump minor"
- Breaking change: Still 1.6.1 unless user says "bump major"

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

## ⚠️ CRITICAL: Never Abandon Planned Work

**When something is complicated, DO NOT ignore it or refuse to implement it.**

Instead:
1. **Create detailed issues** breaking down the complexity into manageable parts
2. **Create detailed todos** tracking each step
3. **Create plans/docs** explaining the approach and challenges
4. **Implement it** in the next session or continue working through the complexity

**Never throw away scheduled work.** If an algorithm is difficult to implement:
- Research the algorithm more thoroughly
- Study reference implementations
- Break it into smaller pieces
- Document what's hard and why
- Create a plan to solve it
- Then implement it

The goal is to implement EVERYTHING we plan to implement. Complexity is not an excuse to skip work.

## ⚠️ CRITICAL: Don't Half-Ass It

**Always do the whole thing. Don't quit at 80%.**

- If you can't complete something now, create a GitHub issue for later
- Never leave work partially done without tracking
- If a label doesn't exist, CREATE IT, then add it to the issue
- If you encounter blockers, document them and create issues
- Complete all follow-up tasks (docs, tests, issues, labels)

**GitHub Issue Management:**
- **ALWAYS create missing labels** - Never skip labels because they don't exist
- Use `gh label create` to create missing labels first
- Then create/update the issue with proper labels
- Labels should include: `performance`, `bug`, `enhancement`, `documentation`, `investigation`, `high-priority`, `medium-priority`, `low-priority`

## ⚠️ CRITICAL: Never Revert to External Libraries When Things Get Hard

**Reverting to BouncyCastle or other external libraries is ALWAYS a last resort.**

When implementing native algorithms and encountering bugs or difficulties:
1. **Research first** - Study the algorithm specification, reference implementations, and papers
2. **Debug systematically** - Use test vectors, check constants, verify byte order
3. **Break down the problem** - Identify exactly which part is failing
4. **Plan the fix** - Document what needs to change before making changes
5. **Implement the fix** - Apply the fix methodically, testing each step
6. **Create issues if blocked** - If truly stuck, create a detailed issue for later

**NEVER:**
- Give up at the first sign of difficulty
- Immediately revert to BouncyCastle when tests fail
- Abandon native implementations because they're "too complex"
- Throw away working code because one part has a bug

**Reverting is only acceptable when:**
- The algorithm is fundamentally incompatible with our architecture
- After exhaustive debugging and research (document attempts)
- With explicit user approval

