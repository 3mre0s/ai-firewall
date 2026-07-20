# Anonmyz judge guide

## Two-minute setup — no API key

Prerequisite: Go 1.22+, or use the matching prebuilt binary from `dist/`.

```bash
git clone https://github.com/3mre0s/ai-firewall.git
cd ai-firewall
go build -trimpath -o anonmyz .
./anonmyz demo --non-interactive
```

Windows PowerShell:

```powershell
git clone https://github.com/3mre0s/ai-firewall.git
Set-Location ai-firewall
go build -trimpath -o anonmyz.exe .
.\anonmyz.exe demo --non-interactive
```

The demo is deterministic, uses only loopback networking, runs the production masking/restoration pipeline, and exits non-zero if an original value reaches the mock upstream or restoration fails.

## Fail-closed proof — no API key

With the Codex CLI installed:

```bash
go run ./scripts/verify-codex-fail-closed
```

The probe uses a synthetic local-only authentication canary. It terminates the real loopback Anonmyz proxy during an in-flight Codex request and requires all of the following: Codex exits with an error, direct model fallback attempts equal zero, and the canary is absent from output.

## Optional live Codex proof

Use an existing ChatGPT login and only an unmistakably fake secret-shaped value:

```bash
codex login
./anonmyz codex --dry-run -- --no-alt-screen
./anonmyz codex -- exec --ignore-user-config --ephemeral "Repeat only this fake test value: ghp_FAKEDEMO0000000000000000000000000000"
```

Expected metadata-only evidence includes `status=200`, `detections=1`, `prevented=true`, at least one restored placeholder, `response_blocked=false`, and `VERIFIED`.

Never place a real credential in the test prompt, recording, issue, or submission form.
