# Cross-compile Anonmyz and the ai-firewall compatibility binary.
# Usage: pwsh scripts/build-all.ps1 [version]
#   version: optional tag (default: dev)

[CmdletBinding()]
param(
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
$usingLocalGoCache = [string]::IsNullOrWhiteSpace($env:GOCACHE)
if ($usingLocalGoCache) {
    $env:GOCACHE = Join-Path $root ".gocache"
}

if (Test-Path -LiteralPath $dist) {
    Remove-Item -LiteralPath $dist -Recurse -Force
}
New-Item -ItemType Directory -Path $dist | Out-Null

$targets = @(
    @{ GOOS = "linux";   GOARCH = "amd64"; Asset = "anonmyz-linux-amd64";       Legacy = "ai-firewall-linux-amd64"       },
    @{ GOOS = "linux";   GOARCH = "arm64"; Asset = "anonmyz-linux-arm64";       Legacy = "ai-firewall-linux-arm64"       },
    @{ GOOS = "darwin";  GOARCH = "amd64"; Asset = "anonmyz-darwin-amd64";      Legacy = "ai-firewall-darwin-amd64"      },
    @{ GOOS = "darwin";  GOARCH = "arm64"; Asset = "anonmyz-darwin-arm64";      Legacy = "ai-firewall-darwin-arm64"      },
    @{ GOOS = "windows"; GOARCH = "amd64"; Asset = "anonmyz-windows-amd64.exe"; Legacy = "ai-firewall-windows-amd64.exe" }
)

Push-Location $root
try {
    foreach ($t in $targets) {
        $out = Join-Path $dist $t.Asset
        Write-Host "→ building $($t.GOOS)/$($t.GOARCH) → $out"
        $env:CGO_ENABLED = "0"
        $env:GOOS        = $t.GOOS
        $env:GOARCH      = $t.GOARCH
        & go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$Version" -o $out .
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $($t.GOOS)/$($t.GOARCH)"
        }
        $hash = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLower()
        "$hash  $($t.Asset)" | Out-File -FilePath "$out.sha256" -Encoding ascii -NoNewline

		$legacyOut = Join-Path $dist $t.Legacy
		& go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$Version" -o $legacyOut .
		if ($LASTEXITCODE -ne 0) {
			throw "legacy go build failed for $($t.GOOS)/$($t.GOARCH)"
		}
		$legacyHash = (Get-FileHash -LiteralPath $legacyOut -Algorithm SHA256).Hash.ToLower()
		"$legacyHash  $($t.Legacy)" | Out-File -FilePath "$legacyOut.sha256" -Encoding ascii -NoNewline
    }
}
finally {
    Remove-Item Env:CGO_ENABLED, Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
    if ($usingLocalGoCache) {
        Remove-Item Env:GOCACHE -ErrorAction SilentlyContinue
    }
    Pop-Location
}

Write-Host ""
Write-Host "Artifacts in $dist :"
Get-ChildItem -LiteralPath $dist | Format-Table Name, Length

Get-ChildItem -LiteralPath $dist -File |
    Where-Object { $_.Name -notlike "*.sha256" -and $_.Name -ne "checksums.txt" } |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
        "$hash  $($_.Name)"
    } | Out-File -FilePath (Join-Path $dist "checksums.txt") -Encoding ascii
