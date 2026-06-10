# End-to-end smoke test against a REAL upstream provider.
#
# Usage:
#   $env:FORWARD_API_KEY = "sk-..."
#   pwsh scripts/e2e-live.ps1 anthropic
#   pwsh scripts/e2e-live.ps1 openai
#
# Exits non-zero on any failure. NEVER runs in CI — it would leak your key.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("anthropic", "openai")]
    [string]$Provider,

    [int]$Port = 18080
)

$ErrorActionPreference = "Stop"

if (-not $env:FORWARD_API_KEY) {
    Write-Error "FORWARD_API_KEY is not set. Aborting before we start the firewall."
}

$root = Split-Path -Parent $PSScriptRoot

# Pick the right binary for the host
$binary = if ($IsWindows -or $env:OS -eq "Windows_NT") {
    Join-Path $root "ai-firewall.exe"
} else {
    Join-Path $root "ai-firewall"
}

if (-not (Test-Path -LiteralPath $binary)) {
    Write-Host "→ binary missing, building: $binary"
    Push-Location $root
    try { & go build -o $binary . } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "go build failed" }
}

switch ($Provider) {
    "anthropic" {
        $upstream = "https://api.anthropic.com"
        $hint     = "anthropic"
        $path     = "/v1/messages"
        $headers  = @{
            "Content-Type"      = "application/json"
            "anthropic-version" = "2023-06-01"
        }
        $body = @{
            model      = "claude-3-5-haiku-20241022"
            max_tokens = 32
            messages   = @(@{ role = "user"; content = "Reply with exactly: ok" })
        } | ConvertTo-Json -Depth 6
    }
    "openai" {
        $upstream = "https://api.openai.com"
        $hint     = "openai"
        $path     = "/v1/chat/completions"
        $headers  = @{ "Content-Type" = "application/json" }
        $body = @{
            model      = "gpt-4o-mini"
            max_tokens = 32
            messages   = @(@{ role = "user"; content = "Reply with exactly: ok" })
        } | ConvertTo-Json -Depth 6
    }
}

# Boot the firewall in the background
$logFile = Join-Path ([IO.Path]::GetTempPath()) "ai-firewall-e2e.log"
if (Test-Path -LiteralPath $logFile) { Remove-Item -LiteralPath $logFile -Force }

$envVars = @{
    FORWARD_API_KEY = $env:FORWARD_API_KEY
    UPSTREAM_URL    = $upstream
    PROVIDER_HINT   = $hint
    FIREWALL_PORT   = "$Port"
    LOG_LEVEL       = "debug"
}

Write-Host "→ starting firewall on :$Port → $upstream ($hint)"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $binary
$psi.WorkingDirectory = $root
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
foreach ($kv in $envVars.GetEnumerator()) { $psi.Environment[$kv.Key] = $kv.Value }

$proc = [System.Diagnostics.Process]::Start($psi)
$stdoutTask = $proc.StandardOutput.ReadToEndAsync()
$stderrTask = $proc.StandardError.ReadToEndAsync()

try {
    # Wait for /health
    $healthy = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 200
        try {
            $h = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 2 -UseBasicParsing
            if ($h.StatusCode -eq 200) { $healthy = $true; break }
        } catch { }
    }
    if (-not $healthy) { throw "firewall did not become healthy within 6s" }
    Write-Host "✓ /health ok"

    # Fire the real request
    $uri = "http://127.0.0.1:$Port$path"
    Write-Host "→ POST $uri"

    $resp = Invoke-WebRequest `
        -Uri $uri `
        -Method POST `
        -Headers $headers `
        -Body $body `
        -TimeoutSec 60 `
        -UseBasicParsing `
        -SkipHttpErrorCheck

    Write-Host "← status: $($resp.StatusCode)"
    Write-Host "← headers (relevant):"
    foreach ($h in @("Content-Type", "x-request-id", "anthropic-ratelimit-requests-remaining", "x-ratelimit-remaining-requests")) {
        $v = $resp.Headers[$h]
        if ($v) { Write-Host "  $h : $v" }
    }
    Write-Host "← body (first 400 chars):"
    $bodyText = if ($resp.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($resp.Content) } else { [string]$resp.Content }
    Write-Host ($bodyText.Substring(0, [Math]::Min(400, $bodyText.Length)))

    # Metrics
    $metrics = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/metrics" -UseBasicParsing
    Write-Host ""
    Write-Host "/metrics:"
    Write-Host $metrics.Content

    if ($resp.StatusCode -ge 400) {
        throw "upstream returned $($resp.StatusCode). Check headers above — this is exactly the kind of header bug task #4 is meant to catch."
    }
    Write-Host ""
    Write-Host "✓ live test PASSED for $Provider"
}
finally {
    if ($proc -and -not $proc.HasExited) {
        Write-Host "→ stopping firewall (pid $($proc.Id))"
        $proc.Kill()
        $proc.WaitForExit(5000) | Out-Null
    }
    if ($stdoutTask) { $stdoutTask.Result | Out-File -FilePath $logFile -Encoding utf8 -Append }
    if ($stderrTask) { $stderrTask.Result | Out-File -FilePath $logFile -Encoding utf8 -Append }
    Write-Host "firewall log: $logFile"
}
