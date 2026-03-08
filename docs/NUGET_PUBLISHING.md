# 📦 NuGet Package Publishing Guide

This guide provides step-by-step instructions for publishing the StreamHash package to NuGet.org.

## 🔐 One-Time Setup: Get Your API Key

### Step 1: Create a NuGet.org Account

1. Go to **[https://www.nuget.org/](https://www.nuget.org/)**
2. Click **"Sign in"** (top right)
3. Sign in with Microsoft account, or create one
4. Complete email verification if prompted

### Step 2: Create an API Key

1. Go to **[https://www.nuget.org/account/apikeys](https://www.nuget.org/account/apikeys)**
2. Click **"Create"** button
3. Fill in the form:
	- **Key name**: `StreamHash Publishing Key` (or any name you want)
	- **Expiration**: 365 days (maximum)
	- **Glob pattern**: `StreamHash*` (limits scope to this package)
	- **Available scopes**: ✅ Push new packages and package versions
4. Click **"Create"**
5. **IMPORTANT**: Copy the API key immediately! You won't be able to see it again.

### Step 3: Store Your API Key Securely

Store the API key in a secure location. Options:

- **Windows Credential Manager**
- **Environment variable** (for CI/CD)
- **Encrypted file**

For local use, you can set an environment variable:

```powershell
# PowerShell - Session only
$env:NUGET_API_KEY = "your-api-key-here"

# Or permanently (User level)
[Environment]::SetEnvironmentVariable("NUGET_API_KEY", "your-api-key-here", "User")
```

---

## 📤 Publishing the Package

### Method 1: Using dotnet CLI (Recommended)

1. **Build the package** (if not already built):

	```powershell
	cd C:\Users\me\source\repos\StreamHash
	dotnet pack src\StreamHash.Core\StreamHash.Core.csproj -c Release -o .\nupkg
	```

2. **Push to NuGet.org**:

	```powershell
	dotnet nuget push nupkg\StreamHash.1.6.1.nupkg --api-key $env:NUGET_API_KEY --source https://api.nuget.org/v3/index.json
	```

3. **Push symbols package** (for debugging):

	```powershell
	dotnet nuget push nupkg\StreamHash.1.6.1.snupkg --api-key $env:NUGET_API_KEY --source https://api.nuget.org/v3/index.json
	```

### Method 2: Using nuget.exe CLI

1. **Download nuget.exe**: [https://www.nuget.org/downloads](https://www.nuget.org/downloads)

2. **Push the package**:

	```powershell
	nuget push nupkg\StreamHash.1.6.1.nupkg -ApiKey $env:NUGET_API_KEY -Source https://api.nuget.org/v3/index.json
	```

### Method 3: Manual Upload via Website

1. Go to **[https://www.nuget.org/packages/manage/upload](https://www.nuget.org/packages/manage/upload)**
2. Click **"Browse"** and select `StreamHash.1.6.1.nupkg`
3. Review the package metadata
4. Click **"Submit"**

---

## ⏳ After Publishing

### Validation Time

- Package uploads are typically validated within **15-30 minutes**
- Package will appear on NuGet.org search after validation
- Package page: **[https://www.nuget.org/packages/StreamHash](https://www.nuget.org/packages/StreamHash)**

### Verify Installation Works

```powershell
# Create a test project
mkdir test-streamhash
cd test-streamhash
dotnet new console
dotnet add package StreamHash --version 1.6.1
```

---

## 🔄 Future Releases

1. **Update version** in `StreamHash.Core.csproj`:

	```xml
	<Version>1.7.0</Version>
	<PackageReleaseNotes>v1.7.0: Description of changes</PackageReleaseNotes>
	```

2. **Build and publish**:

	```powershell
	dotnet pack src\StreamHash.Core\StreamHash.Core.csproj -c Release -o .\nupkg
	dotnet nuget push nupkg\StreamHash.1.7.0.nupkg --api-key $env:NUGET_API_KEY --source https://api.nuget.org/v3/index.json
	```

---

## 🔗 Important URLs

| Resource | URL |
|----------|-----|
| NuGet.org | [https://www.nuget.org/](https://www.nuget.org/) |
| Sign In | [https://www.nuget.org/users/account/LogOn](https://www.nuget.org/users/account/LogOn) |
| API Keys | [https://www.nuget.org/account/apikeys](https://www.nuget.org/account/apikeys) |
| Upload Package | [https://www.nuget.org/packages/manage/upload](https://www.nuget.org/packages/manage/upload) |
| Package Page | [https://www.nuget.org/packages/StreamHash](https://www.nuget.org/packages/StreamHash) |
| NuGet CLI Download | [https://www.nuget.org/downloads](https://www.nuget.org/downloads) |
| Push API Endpoint | `https://api.nuget.org/v3/index.json` |

---

## 🛡️ Security Best Practices

1. **Never commit API keys** to source control
2. **Use scoped API keys** with glob patterns (e.g., `StreamHash*`)
3. **Set expiration** on API keys (365 days max)
4. **Regenerate keys** periodically
5. **Use environment variables** for CI/CD

---

## 📋 Package Checklist Before Publishing

- [ ] Version number updated in `.csproj`
- [ ] Release notes updated
- [ ] All tests pass (`dotnet test`)
- [ ] README.md is up to date
- [ ] LICENSE file included
- [ ] Package builds successfully (`dotnet pack`)
- [ ] Package verified locally

---

## 🆘 Troubleshooting

### "Package already exists"

The version has already been published. Increment the version number.

### "API key is invalid"

- Check the key hasn't expired
- Verify the glob pattern matches your package name
- Ensure the key has push permissions

### "Package validation failed"

- Check the `.nuspec` metadata in the `.nupkg` file
- Ensure README.md and LICENSE are included
- Verify TargetFramework is valid

### Package not showing in search

- Wait 15-30 minutes for indexing
- Check package page directly: `https://www.nuget.org/packages/StreamHash`
