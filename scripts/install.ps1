$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repository = "3mre0s/ai-firewall"
$version = if ($env:ANONMYZ_VERSION) { $env:ANONMYZ_VERSION } else { "latest" }
$installDirectory = if ($env:ANONMYZ_INSTALL_DIR) {
    $env:ANONMYZ_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA "Programs\Anonmyz"
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "Anonmyz requires 64-bit Windows."
}

$archive = "anonmyz-windows-amd64.zip"
if ($version -eq "latest") {
    $baseUrl = "https://github.com/$repository/releases/latest/download"
} else {
    $tag = if ($version.StartsWith("v")) { $version } else { "v$version" }
    $baseUrl = "https://github.com/$repository/releases/download/$tag"
}

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("anonmyz-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

try {
    $archivePath = Join-Path $temporaryDirectory $archive
    $checksumsPath = Join-Path $temporaryDirectory "checksums.txt"

    Write-Host "Downloading $archive..."
    Invoke-WebRequest "$baseUrl/$archive" -OutFile $archivePath
    Invoke-WebRequest "$baseUrl/checksums.txt" -OutFile $checksumsPath

    $escapedArchive = [regex]::Escape($archive)
    $checksumLine = Get-Content $checksumsPath | Where-Object { $_ -match "^([a-fA-F0-9]{64})\s+\*?$escapedArchive$" } | Select-Object -First 1
    if (-not $checksumLine) {
        throw "$archive is missing from checksums.txt."
    }

    $expected = ([regex]::Match($checksumLine, "^[a-fA-F0-9]{64}")).Value.ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Checksum verification failed."
    }

    $expandedDirectory = Join-Path $temporaryDirectory "expanded"
    Expand-Archive -Path $archivePath -DestinationPath $expandedDirectory
    New-Item -ItemType Directory -Force -Path $installDirectory | Out-Null
    Copy-Item (Join-Path $expandedDirectory "anonmyz.exe") (Join-Path $installDirectory "anonmyz.exe") -Force

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathEntries = @($userPath -split ";" | Where-Object { $_ })
    if ($installDirectory -notin $pathEntries) {
        [Environment]::SetEnvironmentVariable("Path", ((@($pathEntries) + $installDirectory) -join ";"), "User")
    }
    if ($installDirectory -notin ($env:Path -split ";")) {
        $env:Path = "$installDirectory;$env:Path"
    }

    Write-Host "Installed anonmyz.exe to $installDirectory (SHA-256 verified)." -ForegroundColor Green
    Write-Host "Run: anonmyz demo --non-interactive"
} finally {
    $systemTemporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $resolvedTemporaryDirectory = [IO.Path]::GetFullPath($temporaryDirectory)
    $isInstallerTemporaryDirectory = (Split-Path $resolvedTemporaryDirectory -Leaf).StartsWith("anonmyz-install-")
    if ($isInstallerTemporaryDirectory -and $resolvedTemporaryDirectory.StartsWith($systemTemporaryRoot) -and (Test-Path -LiteralPath $resolvedTemporaryDirectory)) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
