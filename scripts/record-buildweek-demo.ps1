param(
    [switch]$DryRun,
    [switch]$SkipOBS,
    [switch]$RunLiveCodex,
    [int]$TargetSeconds = 170,
    [string]$OutputDir = ".\submission\video-out",
    [string]$ObsWebSocketUrl = "ws://127.0.0.1:4455",
    [string]$ObsWebSocketPassword = $env:OBS_WEBSOCKET_PASSWORD
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outDir = Join-Path $root $OutputDir
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$startedAt = Get-Date
$transcriptPath = Join-Path $outDir "terminal-transcript.txt"
$narrationPath = Join-Path $outDir "narration.wav"
$srtPath = Join-Path $outDir "captions.srt"
$finalPath = Join-Path $outDir "anonmyz-buildweek-demo.mp4"

function Write-DemoLine {
    param([string]$Text, [string]$Color = "Gray")
    Write-Host $Text -ForegroundColor $Color
    Add-Content -LiteralPath $transcriptPath -Value $Text
}

function Invoke-DemoCommand {
    param(
        [string]$Title,
        [string]$Command,
        [int]$PauseSeconds = 2
    )
    Write-DemoLine ""
    Write-DemoLine "PS $root> $Command" "Cyan"
    if ($DryRun) {
        Write-DemoLine "[DRY RUN] $Title"
        return
    }
    Push-Location $root
    try {
        $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $Command 2>&1
        foreach ($line in $output) {
            Write-DemoLine ([string]$line)
        }
    } finally {
        Pop-Location
    }
    Start-Sleep -Seconds $PauseSeconds
}

function Resolve-FFmpeg {
    $cmd = Get-Command ffmpeg.exe -ErrorAction SilentlyContinue
    if ($cmd -and (Test-Path -LiteralPath $cmd.Source)) {
        return $cmd.Source
    }
    $wingetLink = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\ffmpeg.exe"
    if (Test-Path -LiteralPath $wingetLink) {
        $item = Get-Item -LiteralPath $wingetLink
        if ($item.Target -and (Test-Path -LiteralPath $item.Target[0])) {
            return $item.Target[0]
        }
    }
    return $null
}

function Resolve-OBS {
    $candidates = @(
        "C:\Program Files\obs-studio\bin\64bit\obs64.exe",
        "C:\Program Files (x86)\obs-studio\bin\64bit\obs64.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    $cmd = Get-Command obs64.exe, obs.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) {
        return $cmd.Source
    }
    return $null
}

function ConvertTo-Base64Sha256 {
    param([string]$Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    return [Convert]::ToBase64String($sha.ComputeHash($bytes))
}

function New-ObsSocket {
    param([string]$Url, [string]$Password)
    Add-Type -AssemblyName System.Net.WebSockets.Client
    $socket = [System.Net.WebSockets.ClientWebSocket]::new()
    $socket.ConnectAsync([Uri]$Url, [Threading.CancellationToken]::None).GetAwaiter().GetResult()

    function Receive-ObsJson {
        param($Socket)
        $buffer = New-Object byte[] 65536
        $segment = [ArraySegment[byte]]::new($buffer)
        $builder = [System.Text.StringBuilder]::new()
        do {
            $result = $Socket.ReceiveAsync($segment, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            if ($result.Count -gt 0) {
                [void]$builder.Append([System.Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count))
            }
        } while (-not $result.EndOfMessage)
        return ($builder.ToString() | ConvertFrom-Json)
    }

    function Send-ObsJson {
        param($Socket, $Payload)
        $json = $Payload | ConvertTo-Json -Depth 10 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $segment = [ArraySegment[byte]]::new($bytes)
        $Socket.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    }

    $hello = Receive-ObsJson $socket
    $identify = @{ op = 1; d = @{ rpcVersion = 1; eventSubscriptions = 0 } }
    if ($hello.d.authentication) {
        if ([string]::IsNullOrWhiteSpace($Password)) {
            throw "OBS WebSocket requires a password. Set OBS_WEBSOCKET_PASSWORD or disable authentication in OBS."
        }
        $secret = ConvertTo-Base64Sha256 ($Password + $hello.d.authentication.salt)
        $auth = ConvertTo-Base64Sha256 ($secret + $hello.d.authentication.challenge)
        $identify.d.authentication = $auth
    }
    Send-ObsJson $socket $identify
    $identified = Receive-ObsJson $socket
    if ($identified.op -ne 2) {
        throw "OBS WebSocket identify failed."
    }
    return $socket
}

function Invoke-ObsRequest {
    param($Socket, [string]$RequestType)
    $requestId = [Guid]::NewGuid().ToString("N")
    $payload = @{ op = 6; d = @{ requestType = $RequestType; requestId = $requestId } }
    $json = $payload | ConvertTo-Json -Depth 10 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $segment = [ArraySegment[byte]]::new($bytes)
    $Socket.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()

    $buffer = New-Object byte[] 65536
    $receiveSegment = [ArraySegment[byte]]::new($buffer)
    while ($true) {
        $builder = [System.Text.StringBuilder]::new()
        do {
            $result = $Socket.ReceiveAsync($receiveSegment, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            if ($result.Count -gt 0) {
                [void]$builder.Append([System.Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count))
            }
        } while (-not $result.EndOfMessage)
        $message = $builder.ToString() | ConvertFrom-Json
        if ($message.op -eq 7 -and $message.d.requestId -eq $requestId) {
            if (-not $message.d.requestStatus.result) {
                throw "OBS request $RequestType failed: $($message.d.requestStatus.comment)"
            }
            return $message.d.responseData
        }
    }
}

function Start-DemoRecording {
    if ($SkipOBS -or $DryRun) {
        return $null
    }
    try {
        $socket = New-ObsSocket -Url $ObsWebSocketUrl -Password $ObsWebSocketPassword
        Invoke-ObsRequest -Socket $socket -RequestType "StartRecord" | Out-Null
        Write-DemoLine "[OBS] Recording started through WebSocket." "Green"
        return @{ Mode = "WebSocket"; Socket = $socket }
    } catch {
        Write-DemoLine "[OBS] WebSocket control unavailable: $($_.Exception.Message)" "Yellow"
    }

    $obs = Resolve-OBS
    if (-not $obs) {
        Write-DemoLine "[OBS] OBS was not found. Run with -SkipOBS to produce assets only." "Yellow"
        return $null
    }
    $obsDir = Split-Path -Parent $obs
    $process = Start-Process -FilePath $obs -ArgumentList "--startrecording", "--minimize-to-tray" -WorkingDirectory $obsDir -PassThru
    Start-Sleep -Seconds 6
    Write-DemoLine "[OBS] Recording started by launching OBS. If prompted, allow recording." "Green"
    return @{ Mode = "Process"; Process = $process }
}

function Stop-DemoRecording {
    param($Recording)
    if (-not $Recording) {
        return $null
    }
    if ($Recording.Mode -eq "WebSocket") {
        $data = Invoke-ObsRequest -Socket $Recording.Socket -RequestType "StopRecord"
        $Recording.Socket.Dispose()
        Write-DemoLine "[OBS] Recording stopped through WebSocket." "Green"
        return $data.outputPath
    }
    if ($Recording.Mode -eq "Process") {
        $process = $Recording.Process
        if ($process -and -not $process.HasExited) {
            [void]$process.CloseMainWindow()
            Start-Sleep -Seconds 5
        }
        Write-DemoLine "[OBS] Stop requested by closing OBS. Check OBS if it asks for confirmation." "Yellow"
        return $null
    }
}

function Get-NewestRecording {
    param([datetime]$After)
    $videos = [Environment]::GetFolderPath("MyVideos")
    $candidates = @($outDir, $videos) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    Get-ChildItem -LiteralPath $candidates -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $After -and $_.Length -gt 0 -and $_.Extension -in @(".mp4", ".mkv", ".mov") } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}

function New-NarrationAssets {
    $segments = @(
        @{ Start = 0; Text = "Coding agents can receive stack traces, local paths, passwords, and credentials before anyone notices. Anonmyz is a local first DLP gateway for that moment." },
        @{ Start = 18; Text = "The deterministic proof is one command. It needs no API key, starts the real proxy and a local mock model, and fails closed if any invariant breaks." },
        @{ Start = 55; Text = "The demo proves four fake sensitive values were replaced with placeholders before upstream, and that a placeholder split across streamed writes was restored locally." },
        @{ Start = 82; Text = "For the Codex workflow, the retained live evidence used an existing ChatGPT subscription and one intentionally fake GitHub token shaped value. No real credential was retained." },
        @{ Start = 112; Text = "The fail closed probe terminates the loopback proxy during an in flight Codex request. Codex exits with an error and makes zero direct model fallback attempts." },
        @{ Start = 140; Text = "The audit trail is local and metadata only: type, placeholder, request id, prevention, latency, upstream status, and restoration. No raw values, bodies, or hashes are stored." },
        @{ Start = 160; Text = "Anonmyz turns the security claim into executable evidence: deterministic local DLP and protected Codex traffic in a single Go binary." }
    )

    $srt = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $segments.Count; $i++) {
        $start = [TimeSpan]::FromSeconds($segments[$i].Start)
        $endSeconds = if ($i -lt $segments.Count - 1) { $segments[$i + 1].Start - 1 } else { $TargetSeconds - 1 }
        $end = [TimeSpan]::FromSeconds($endSeconds)
        $srt.Add(($i + 1).ToString())
        $srt.Add(("{0:hh\:mm\:ss\,fff} --> {1:hh\:mm\:ss\,fff}" -f $start, $end))
        $srt.Add($segments[$i].Text)
        $srt.Add("")
    }
    Set-Content -LiteralPath $srtPath -Value $srt -Encoding UTF8

    if ($DryRun) {
        return
    }
    Add-Type -AssemblyName System.Speech
    $speaker = [System.Speech.Synthesis.SpeechSynthesizer]::new()
    $speaker.Rate = 1
    $speaker.Volume = 100
    $speaker.SetOutputToWaveFile($narrationPath)
    foreach ($segment in $segments) {
        $speaker.Speak($segment.Text)
    }
    $speaker.Dispose()
}

function New-FinalVideo {
    param([string]$RawRecording)
    if ($DryRun) {
        return
    }
    $ffmpeg = Resolve-FFmpeg
    if (-not $ffmpeg) {
        Write-DemoLine "[VIDEO] ffmpeg was not found. Raw recording: $RawRecording" "Yellow"
        return
    }
    if (-not $RawRecording -or -not (Test-Path -LiteralPath $RawRecording)) {
        Write-DemoLine "[VIDEO] No usable OBS recording was found. Creating a terminal-style fallback video." "Yellow"
        $RawRecording = New-SyntheticRecording -FFmpeg $ffmpeg
    }
    $mediaTemp = "C:\tmp\anonmyz-buildweek-video"
    New-Item -ItemType Directory -Force -Path $mediaTemp | Out-Null
    $rawForFFmpeg = Join-Path $mediaTemp "raw-input.mp4"
    $narrationForFFmpeg = Join-Path $mediaTemp "narration.wav"
    $srtForFFmpeg = Join-Path $mediaTemp "captions.srt"
    $finalForFFmpeg = Join-Path $mediaTemp "anonmyz-buildweek-demo.mp4"
    Copy-Item -LiteralPath $RawRecording -Destination $rawForFFmpeg -Force
    Copy-Item -LiteralPath $narrationPath -Destination $narrationForFFmpeg -Force
    Copy-Item -LiteralPath $srtPath -Destination $srtForFFmpeg -Force

    $zoom = "crop=w='if(between(t,20,65),iw*0.82,if(between(t,112,140),iw*0.84,iw))':h='if(between(t,20,65),ih*0.82,if(between(t,112,140),ih*0.84,ih))':x='(iw-ow)/2':y='(ih-oh)*0.35',scale=1920:1080"
    $args = @(
        "-y",
        "-i", $rawForFFmpeg,
        "-i", $narrationForFFmpeg,
        "-i", $srtForFFmpeg,
        "-map", "0:v:0",
        "-map", "1:a:0",
        "-map", "2:0",
        "-vf", $zoom,
        "-c:v", "libx264",
        "-preset", "veryfast",
        "-crf", "22",
        "-c:a", "aac",
        "-b:a", "160k",
        "-af", "apad",
        "-c:s", "mov_text",
        "-movflags", "+faststart",
        "-t", "$TargetSeconds",
        $finalForFFmpeg
    )
    & $ffmpeg @args
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $finalForFFmpeg)) {
        throw "ffmpeg failed to create final MP4."
    }
    Move-Item -LiteralPath $finalForFFmpeg -Destination $finalPath -Force
    Write-DemoLine "[VIDEO] Final MP4: $finalPath" "Green"
}

function New-SyntheticRecording {
    param([string]$FFmpeg)
    Add-Type -AssemblyName System.Drawing
    $slidesDir = "C:\tmp\anonmyz-buildweek-video\slides"
    New-Item -ItemType Directory -Force -Path $slidesDir | Out-Null
    $lines = Get-Content -LiteralPath $transcriptPath
    $chunks = New-Object System.Collections.Generic.List[object]
    $chunk = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        $chunk.Add($line)
        if ($chunk.Count -ge 23) {
            $chunks.Add(@($chunk.ToArray()))
            $chunk.Clear()
        }
    }
    if ($chunk.Count -gt 0) {
        $chunks.Add(@($chunk.ToArray()))
    }
    if ($chunks.Count -eq 0) {
        $chunks.Add(@("Anonmyz Build Week demo"))
    }

    $fontTitle = [System.Drawing.Font]::new("Consolas", 28, [System.Drawing.FontStyle]::Bold)
    $font = [System.Drawing.Font]::new("Consolas", 24, [System.Drawing.FontStyle]::Regular)
    $brushText = [System.Drawing.Brushes]::Gainsboro
    $brushAccent = [System.Drawing.Brushes]::MediumAquamarine
    $brushDim = [System.Drawing.Brushes]::DarkGray
    $format = [System.Drawing.StringFormat]::new()
    $format.Trimming = [System.Drawing.StringTrimming]::EllipsisCharacter
    $format.FormatFlags = [System.Drawing.StringFormatFlags]::NoWrap

    $concatPath = Join-Path $slidesDir "concat.txt"
    $concat = New-Object System.Collections.Generic.List[string]
    $duration = [Math]::Max(2, [Math]::Floor($TargetSeconds / [Math]::Max(1, $chunks.Count)))
    for ($i = 0; $i -lt $chunks.Count; $i++) {
        $path = Join-Path $slidesDir ("slide-{0:D3}.png" -f $i)
        $bitmap = [System.Drawing.Bitmap]::new(1920, 1080)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.Clear([System.Drawing.Color]::FromArgb(12, 16, 18))
        $graphics.FillRectangle([System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(27, 35, 38)), 0, 0, 1920, 86)
        $graphics.DrawString("Anonmyz Build Week Demo", $fontTitle, $brushAccent, 48, 22)
        $graphics.DrawString(("Slide {0}/{1}" -f ($i + 1), $chunks.Count), $font, $brushDim, 1650, 30)
        $y = 120
        foreach ($line in $chunks[$i]) {
            $text = if ($line.Length -gt 118) { $line.Substring(0, 115) + "..." } else { $line }
            $graphics.DrawString($text, $font, $brushText, [System.Drawing.RectangleF]::new(56, $y, 1800, 34), $format)
            $y += 38
            if ($y -gt 1005) {
                break
            }
        }
        $graphics.Dispose()
        $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
        $safe = $path.Replace("\", "/")
        $concat.Add("file '$safe'")
        $concat.Add("duration $duration")
    }
    $last = (Join-Path $slidesDir ("slide-{0:D3}.png" -f ($chunks.Count - 1))).Replace("\", "/")
    $concat.Add("file '$last'")
    Set-Content -LiteralPath $concatPath -Value $concat -Encoding ASCII

    $syntheticPath = "C:\tmp\anonmyz-buildweek-video\synthetic-terminal.mp4"
    & $FFmpeg -y -f concat -safe 0 -i $concatPath -vf "scale=1920:1080,format=yuv420p" -r 30 -t "$TargetSeconds" $syntheticPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $syntheticPath)) {
        throw "ffmpeg failed to create fallback terminal video."
    }
    return $syntheticPath
}

Set-Content -LiteralPath $transcriptPath -Value @(
    "Anonmyz Build Week recording transcript",
    "Started: $startedAt",
    ""
) -Encoding UTF8

Write-DemoLine "Anonmyz Build Week demo automation" "Green"
Write-DemoLine "Output: $outDir"
Write-DemoLine "Keep the terminal large and readable. Do not display real credentials." "Yellow"
Start-Sleep -Seconds 3

$recording = Start-DemoRecording
try {
    Invoke-DemoCommand -Title "Help" -Command ".\anonmyz-recording.exe help"
    Invoke-DemoCommand -Title "Deterministic demo" -Command ".\anonmyz-recording.exe demo --non-interactive" -PauseSeconds 3
    Invoke-DemoCommand -Title "Clean shutdown proof" -Command ".\anonmyz-recording.exe demo --non-interactive" -PauseSeconds 2
    Invoke-DemoCommand -Title "Codex dry run" -Command ".\anonmyz-recording.exe codex --dry-run -- --no-alt-screen" -PauseSeconds 2
    if ($RunLiveCodex) {
        Invoke-DemoCommand -Title "Live Codex smoke test" -Command ".\anonmyz-recording.exe codex -- --no-alt-screen" -PauseSeconds 3
    } else {
        Invoke-DemoCommand -Title "Retained live Codex evidence" -Command "Get-Content -LiteralPath .\evidence\codex-live-dlp-2026-07-20\terminal-session.masked.txt"
        Invoke-DemoCommand -Title "Retained audit evidence" -Command "Get-Content -LiteralPath .\evidence\codex-live-dlp-2026-07-20\audit-summary.masked.json"
    }
    Invoke-DemoCommand -Title "Fail closed probe" -Command "go run .\scripts\verify-codex-fail-closed" -PauseSeconds 2
    Invoke-DemoCommand -Title "Full Go suite" -Command "go test ./... -count=1" -PauseSeconds 2
    Invoke-DemoCommand -Title "Release artifacts" -Command "Get-ChildItem -LiteralPath .\dist -File | Select-Object Name,Length"
} finally {
    $rawRecording = Stop-DemoRecording -Recording $recording
}

if (-not $rawRecording) {
    $rawRecording = Get-NewestRecording -After $startedAt
}
New-NarrationAssets
New-FinalVideo -RawRecording $rawRecording
Write-DemoLine "Done." "Green"
