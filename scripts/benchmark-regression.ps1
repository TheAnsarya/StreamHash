<#
.SYNOPSIS
	Runs benchmarks and compares against a stored baseline for regression detection.
.DESCRIPTION
	This script runs BenchmarkDotNet benchmarks, extracts key metrics from the CSV output,
	and compares them against a baseline file. Reports any regressions exceeding a threshold.
.PARAMETER Filter
	BenchmarkDotNet filter pattern (default: all FileHasherBenchmarks).
.PARAMETER BaselinePath
	Path to the baseline CSV file (default: benchmarks/baseline.csv).
.PARAMETER ThresholdPercent
	Maximum allowed performance degradation percentage (default: 15).
.PARAMETER UpdateBaseline
	If set, updates the baseline with current results instead of comparing.
#>
param(
	[string]$Filter = "*HashFacadeBenchmarks*",
	[string]$BaselinePath = "benchmarks/baseline.csv",
	[double]$ThresholdPercent = 15,
	[switch]$UpdateBaseline
)

$ErrorActionPreference = "Stop"
$projectDir = "benchmarks/StreamHash.Benchmarks/StreamHash.Benchmarks.csproj"
$resultsDir = "BenchmarkDotNet.Artifacts/results"

Write-Host "Running benchmarks with filter: $Filter" -ForegroundColor Cyan
dotnet run --project $projectDir -c Release -- --filter $Filter --job short --exporters csv
if ($LASTEXITCODE -ne 0) {
	Write-Host "Benchmark run failed!" -ForegroundColor Red
	exit 1
}

# Find the latest CSV result
$csvFiles = Get-ChildItem $resultsDir -Filter "*-report.csv" | Sort-Object LastWriteTime -Descending
if ($csvFiles.Count -eq 0) {
	Write-Host "No benchmark CSV results found!" -ForegroundColor Red
	exit 1
}

$latestCsv = $csvFiles[0].FullName
Write-Host "Latest results: $($csvFiles[0].Name)" -ForegroundColor Green

# Parse CSV
$currentResults = Import-Csv $latestCsv | ForEach-Object {
	[PSCustomObject]@{
		Method    = $_.Method
		MeanUs    = [double]($_.Mean -replace ' [μm]?s$', '' -replace ',', '')
		Allocated = $_.Allocated
	}
}

if ($UpdateBaseline) {
	Copy-Item $latestCsv $BaselinePath -Force
	Write-Host "Baseline updated: $BaselinePath" -ForegroundColor Green
	Write-Host "Methods stored: $($currentResults.Count)" -ForegroundColor Green
	exit 0
}

# Compare against baseline
if (-not (Test-Path $BaselinePath)) {
	Write-Host "No baseline found at $BaselinePath. Run with -UpdateBaseline to create one." -ForegroundColor Yellow
	Copy-Item $latestCsv $BaselinePath -Force
	Write-Host "Created initial baseline." -ForegroundColor Green
	exit 0
}

$baselineResults = Import-Csv $BaselinePath | ForEach-Object {
	[PSCustomObject]@{
		Method    = $_.Method
		MeanUs    = [double]($_.Mean -replace ' [μm]?s$', '' -replace ',', '')
		Allocated = $_.Allocated
	}
}

$regressions = @()
$improvements = @()

foreach ($current in $currentResults) {
	$baseline = $baselineResults | Where-Object { $_.Method -eq $current.Method } | Select-Object -First 1
	if ($null -eq $baseline) {
		Write-Host "  NEW: $($current.Method) = $($current.MeanUs) us" -ForegroundColor Cyan
		continue
	}

	if ($baseline.MeanUs -eq 0) { continue }

	$changePercent = (($current.MeanUs - $baseline.MeanUs) / $baseline.MeanUs) * 100

	if ($changePercent -gt $ThresholdPercent) {
		$regressions += [PSCustomObject]@{
			Method          = $current.Method
			BaselineMean    = $baseline.MeanUs
			CurrentMean     = $current.MeanUs
			ChangePercent   = [math]::Round($changePercent, 1)
		}
	} elseif ($changePercent -lt -$ThresholdPercent) {
		$improvements += [PSCustomObject]@{
			Method          = $current.Method
			BaselineMean    = $baseline.MeanUs
			CurrentMean     = $current.MeanUs
			ChangePercent   = [math]::Round($changePercent, 1)
		}
	}
}

if ($improvements.Count -gt 0) {
	Write-Host "`nImprovements (>$ThresholdPercent% faster):" -ForegroundColor Green
	$improvements | Format-Table -AutoSize
}

if ($regressions.Count -gt 0) {
	Write-Host "`nREGRESSIONS DETECTED (>$ThresholdPercent% slower):" -ForegroundColor Red
	$regressions | Format-Table -AutoSize
	Write-Host "Threshold: $ThresholdPercent%. Fix regressions or update baseline with -UpdateBaseline." -ForegroundColor Red
	exit 1
} else {
	Write-Host "`nNo regressions detected (threshold: $ThresholdPercent%)." -ForegroundColor Green
	exit 0
}
