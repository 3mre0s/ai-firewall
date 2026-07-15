# Contributing to Local AI Firewall

> **Draft notice:** This CLA is a draft; consult a legal professional before entering into binding commercial licensing arrangements.

## Contributor License Agreement

By submitting a pull request or otherwise contributing code, documentation, or other materials to this project, you agree to the following terms:

1. **Copyright grant.** You retain copyright in your contribution. You grant the project maintainer(s) a perpetual, worldwide, irrevocable, non-exclusive, royalty-free license to use, reproduce, modify, distribute, and sublicense your contribution as part of this project.

2. **Inbound = outbound.** Your contribution is made available under the same license as the project: GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).

3. **Commercial use by the maintainer.** You additionally grant the project maintainer(s) the right to include your contribution in versions of the software distributed under a separate commercial license. This does not affect your own rights under the AGPL-3.0 or any other license you hold.

4. **Original work.** You confirm that your contribution is your original work (or that you have the right to submit it), and that it does not knowingly infringe any third-party intellectual property rights.

5. **No warranty.** Your contribution is provided "as is", without warranty of any kind.

## How to contribute

### Local setup

Requires Go 1.22 or later. Node.js 20 is needed only for VS Code extension changes.

```bash
git clone https://github.com/3mre0s/ai-firewall.git
cd ai-firewall
go test ./...
go run . demo
```

Use only synthetic credentials in tests, logs, screenshots, and issues. Run the local mock upstream with `go run ./scripts/mock-upstream --port 19999` when testing proxy behavior without contacting an AI provider.

### Before opening a pull request

- Open an issue before starting significant work — alignment up front saves effort.
- Follow the existing code style (`go fmt`, `go vet` clean).
- All submissions must pass `go test ./...`.
- Keep pull requests focused; one logical change per PR.

```bash
gofmt -w .
go vet ./...
go test ./... -race -count=1
go build ./...
```

Never report a real secret or an exploitable vulnerability in a public issue. Follow [SECURITY.md](SECURITY.md) for private disclosure.
