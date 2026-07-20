# Contributing to Local AI Firewall

Thanks for helping improve Local AI Firewall. Security-sensitive changes need small, reviewable patches and tests that demonstrate the intended boundary.

## Local setup

Requirements:

- Go 1.22 or later
- Node.js 20 only when changing the VS Code extension

```bash
git clone https://github.com/3mre0s/ai-firewall.git
cd ai-firewall
go test ./...
go run . version
```

Run the firewall against the local mock upstream in two terminals:

```bash
go run ./scripts/mock-upstream --port 19999
```

```bash
FORWARD_API_KEY=none UPSTREAM_URL=http://127.0.0.1:19999 go run .
```

Send a test request through `http://127.0.0.1:8080`. Use only synthetic credentials in tests, logs, screenshots, and issues.

## Making a change

- Detection pattern: update `patterns/` and add positive, negative, and near-miss cases.
- Provider adapter: update `providers/`, register it, and cover request/response behavior.
- Proxy or vault behavior: include a regression test for the affected trust boundary.
- User-facing behavior: update README, threat model, or changelog when applicable.

Before opening a pull request, run:

```bash
gofmt -w .
go vet ./...
go test ./... -race -count=1
go build ./...
```

For VS Code extension changes:

```bash
cd extensions/vscode
npm ci
npm run package
```

## Pull requests

Keep each pull request focused. Complete the pull-request template, explain security or privacy implications, and link the relevant issue. Open an issue first for large design changes.

Never report a real secret or an exploitable vulnerability in a public issue. Follow [`SECURITY.md`](SECURITY.md) for private disclosure.
