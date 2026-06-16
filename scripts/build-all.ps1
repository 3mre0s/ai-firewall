# Cross-compile ai-firewall for all supported platforms.
# Usage: pwsh scripts/build-all.ps1 [version]
#   version: optional tag (default: dev)

[CmdletBinding()]
param(
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"

if (Test-Path -LiteralPath $dist) {
    Remove-Item -LiteralPath $dist -Recurse -Force
}
New-Item -ItemType Directory -Path $dist | Out-Null

$targets = @(
    @{ GOOS = "linux";   GOARCH = "amd64"; Asset = "ai-firewall-linux-amd64"          },
    @{ GOOS = "darwin";  GOARCH = "amd64"; Asset = "ai-firewall-darwin-amd64"         },
    @{ GOOS = "darwin";  GOARCH = "arm64"; Asset = "ai-firewall-darwin-arm64"         },
    @{ GOOS = "windows"; GOARCH = "amd64"; Asset = "ai-firewall-windows-amd64.exe"    }
)

Push-Location $root
try {
    foreach ($t in $targets) {
        $out = Join-Path $dist $t.Asset
        Write-Host "→ building $($t.GOOS)/$($t.GOARCH) → $out"
        $env:CGO_ENABLED = "0"
        $env:GOOS        = $t.GOOS
        $env:GOARCH      = $t.GOARCH
        & go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $out .
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $($t.GOOS)/$($t.GOARCH)"
        }
        $hash = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLower()
        "$hash  $($t.Asset)" | Out-File -FilePath "$out.sha256" -Encoding ascii -NoNewline
    }
}
finally {
    Remove-Item Env:CGO_ENABLED, Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}

Write-Host ""
Write-Host "Artifacts in $dist :"
Get-ChildItem -LiteralPath $dist | Format-Table Name, Length
