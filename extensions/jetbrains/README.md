# Local AI Firewall for JetBrains IDEs

Run the firewall as a local sidecar from IntelliJ IDEA, GoLand, PyCharm, WebStorm, or another JetBrains IDE.

## Beta install (no Marketplace required)

1. Download the matching `ai-firewall` binary for your OS from the latest GitHub Release and drop it in one of these auto-discovered locations:

   - **Windows**: `%LOCALAPPDATA%\local-ai-firewall\ai-firewall.exe`
   - **macOS**: `~/Library/Application Support/local-ai-firewall/ai-firewall` (or `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`)
   - **Linux**: `~/.local/bin/ai-firewall` (or `/usr/local/bin`)

   Anywhere on `PATH` also works. To override, set `AI_FIREWALL_BINARY=/full/path/to/ai-firewall`.

2. Install the plugin zip from `Settings > Plugins > ⚙ > Install Plugin from Disk…`.

3. Set `FORWARD_API_KEY=sk-...` in the environment that launches your IDE (login shell, launchd plist, Windows env var), then use `Tools > Local AI Firewall > Start`.

## Development install

1. Build the firewall from the repository root:

   ```bash
   go build -o ai-firewall .
   ```

2. Export environment variables before launching the IDE:

   ```bash
   export FORWARD_API_KEY=sk-your-real-key
   export UPSTREAM_URL=https://api.anthropic.com
   export PROVIDER_HINT=anthropic
   ```

3. From `extensions/jetbrains`, run:

   ```bash
   ./gradlew runIde
   ```

## Commands

Commands are available from `Tools > Local AI Firewall`:

- `Start`
- `Stop`
- `Restart`
- `Copy Agent Env`
- `Open Metrics`

The plugin searches for the binary in this order: `AI_FIREWALL_BINARY` env, project root, OS-standard install dirs, then everything on `PATH`.
