#!/usr/bin/env pwsh
# Build NuGet package for StreamHash

$ErrorActionPreference = "Stop"

Write-Host "Building StreamHash NuGet package..." -ForegroundColor Cyan

Set-Location $PSScriptRoot

# Build the package
dotnet pack src/StreamHash.Core/StreamHash.Core.csproj -c Release -o ./nupkgs

Write-Host "Package build complete!" -ForegroundColor Green
Write-Host "Package location: $PSScriptRoot\nupkgs" -ForegroundColor Yellow

# List the created packages
Get-ChildItem ./nupkgs -Filter "StreamHash.*.nupkg" | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | Format-Table Name, Length, LastWriteTime
