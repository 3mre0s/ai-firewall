# Local AI Firewall for VS Code

Run the firewall as a local sidecar from VS Code.

## Beta install (no Marketplace required)

1. Download `local-ai-firewall.vsix` from the latest GitHub Release.
2. Install it without leaving VS Code:

   ```bash
   code --install-extension local-ai-firewall.vsix
   ```

3. Download the matching `ai-firewall` binary for your OS from the same release and drop it in one of these locations (the extension finds it automatically):

   - **Windows**: `%LOCALAPPDATA%\local-ai-firewall\ai-firewall.exe`
   - **macOS**: `~/Library/Application Support/local-ai-firewall/ai-firewall` (or `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`)
   - **Linux**: `~/.local/bin/ai-firewall` (or `/usr/local/bin`)

   Anywhere on your `PATH` also works. To override, set `localAiFirewall.binaryPath`.

4. Run `Local AI Firewall: Set API Key`, then `Local AI Firewall: Start`.

## Development install

1. Build the firewall from the repository root:

   ```bash
   go build -o ai-firewall .
   ```

2. Open `extensions/vscode` in VS Code.
3. Press `F5` to launch an Extension Development Host.
4. Configure:

   - Run `Local AI Firewall: Set API Key`
   - `localAiFirewall.upstreamUrl`
   - `localAiFirewall.providerHint` when auto-detect is not enough
   - `localAiFirewall.binaryPath` only if the binary is not in any of the standard locations

## Packaging the VSIX

```bash
cd extensions/vscode
npm install
npm run package          # → local-ai-firewall.vsix
```

Beta testers then run `code --install-extension local-ai-firewall.vsix`.

## Commands

- `Local AI Firewall: Start`
- `Local AI Firewall: Stop`
- `Local AI Firewall: Restart`
- `Local AI Firewall: Set API Key`
- `Local AI Firewall: Open Metrics`
- `Local AI Firewall: Copy Agent Env`
