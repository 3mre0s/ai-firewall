# Local AI Firewall — Private Beta

Welcome. This is an **invite-only** beta. Your feedback shapes the v1.0 release.

> Replace the placeholders below before sharing this file publicly:
> `<DISCORD_INVITE_URL>`, `<FEEDBACK_FORM_URL>`, `<RELEASE_TAG>`.

---

## 1. Get an invite

Beta access is granted one tester at a time. To request a slot:

1. Open an issue using the **Beta access request** template, **or**
2. DM the maintainer with your GitHub username and intended use case.

You'll receive a one-time Discord invite: `<DISCORD_INVITE_URL>`

The Discord server is the only realtime support channel during beta. It contains:

- `#announcements` — release tags, breaking changes
- `#install-help` — install / discovery problems per OS
- `#bugs` — reproducible defects (file a GitHub issue too)
- `#ideas` — pattern requests, provider requests, UX ideas

---

## 2. Install the binary

Pick your platform. Drop the file in the auto-discovered location below — both IDE extensions will find it without configuration.

| OS | Binary | Drop-in location |
|---|---|---|
| Windows x64 | `ai-firewall-windows-amd64.exe` → rename to `ai-firewall.exe` | `%LOCALAPPDATA%\local-ai-firewall\` |
| macOS Apple Silicon | `ai-firewall-darwin-arm64` → rename to `ai-firewall` | `~/Library/Application Support/local-ai-firewall/` or `/opt/homebrew/bin` |
| macOS Intel | `ai-firewall-darwin-amd64` → rename to `ai-firewall` | `~/Library/Application Support/local-ai-firewall/` or `/usr/local/bin` |
| Linux x64 | `ai-firewall-linux-amd64` → rename to `ai-firewall` | `~/.local/bin/` or `/usr/local/bin` |

Then verify it can run:

```bash
chmod +x ~/.local/bin/ai-firewall   # macOS / Linux only
ai-firewall --help 2>/dev/null || echo "binary is launchable"
```

Verify the checksum against `checksums.txt` in the same release:

```bash
sha256sum ai-firewall-linux-amd64
# Windows: Get-FileHash ai-firewall-windows-amd64.exe -Algorithm SHA256
```

---

## 3. Install one of the extensions

### VS Code / Cursor

```bash
code --install-extension local-ai-firewall.vsix
```

Then in VS Code:

1. `Local AI Firewall: Set API Key` — paste your real Anthropic / OpenAI key (stored in SecretStorage).
2. `Local AI Firewall: Start`.
3. `Local AI Firewall: Copy Agent Env` and paste the env into your `.env`.

### JetBrains IDEs

1. `Settings → Plugins → ⚙ → Install Plugin from Disk…` and select the plugin zip.
2. Set `FORWARD_API_KEY` in your login shell or IDE launcher env.
3. `Tools → Local AI Firewall → Start`.

---

## 4. Try a real request

Point your AI SDK at the firewall (`Copy Agent Env` does this for you). The firewall replaces `any-placeholder` with your real key before reaching the upstream.

A live smoke test is provided. Set `FORWARD_API_KEY` and run:

```bash
# macOS / Linux
scripts/e2e-live.sh anthropic

# Windows
pwsh scripts/e2e-live.ps1 anthropic
```

Expected: a `200 OK` and a JSON message body. If you see `401` or `400`, capture the response and post it in `#bugs`.

---

## 5. Give feedback

- **Quick survey** (5 questions, ~2 minutes): `<FEEDBACK_FORM_URL>`
- **Bug report**: open an issue with the *Beta feedback* template.
- **Realtime**: post in the relevant Discord channel.

What we most want to hear:

1. Did the binary land in the auto-discovered path on your OS?
2. Did the extension start it on the first try?
3. Did the firewall mask anything you didn't expect, or miss something you did expect?
4. Any provider that returned a header / 4xx error we should look at?

---

## 6. Beta exit criteria

The beta closes when:

- 10 distinct testers complete steps 1–4 on their primary OS.
- No P0 (data leak, secret in logs, crash on start) bugs are open for 7 consecutive days.
- The live smoke test passes against Anthropic **and** OpenAI on all four build targets.

After that, v1.0 ships on GitHub Releases and the VS Code Marketplace.

Thank you for testing.
