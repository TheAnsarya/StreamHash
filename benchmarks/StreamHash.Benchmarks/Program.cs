using BenchmarkDotNet.Running;
using StreamHash.Benchmarks;

BenchmarkSwitcher
	.FromAssembly(typeof(Program).Assembly)
	.Run(args);
