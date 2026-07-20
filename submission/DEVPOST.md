# Anonmyz — keep coding-agent secrets on your machine

Anonmyz is a local-first AI security and DLP gateway for coding agents. It detects supported credentials, passwords, private paths, and PII in request bodies, replaces them with request-scoped placeholders, forwards only sanitized context to the configured model provider, and restores known placeholders locally in standard or streaming responses.

The centerpiece is `anonmyz demo`, a deterministic proof that needs no API key and contacts no external service. It starts the production Anonmyz proxy and a local mock model on dynamic loopback ports, sends four unmistakably fake sensitive values through the real pipeline, and programmatically asserts that the originals are absent from the exact upstream bytes while safe placeholders are present. The mock splits a placeholder across SSE network writes; Anonmyz restores it locally. Any failed invariant produces a non-zero exit code.

`anonmyz codex` launches a protected Codex session using temporary one-run provider overrides. It supports an existing ChatGPT subscription or optional API-key authentication without editing the user's global Codex configuration or reading stored credentials. A retained live test used real ChatGPT subscription traffic with an intentionally fake GitHub PAT-shaped payload. Anonmyz reported one prevented detection, upstream status 200, safe local restoration, and no response block.

The protected model route is fail-closed. An automated probe sends the installed Codex CLI through a real loopback Anonmyz proxy, terminates that proxy during the in-flight request, and traps direct egress. Codex exits with an error and makes zero direct model fallback attempts. The listener is explicitly bound to `127.0.0.1`, never `0.0.0.0`.

A bounded, memory-only local audit trail records only request ID, timestamp, detected type, safe placeholder ID, prevention result, latency, upstream status, and restoration outcome. It never retains request bodies, raw values, secret hashes, OAuth bearer values, ChatGPT account identifiers, or cookies.

Anonmyz is a single cross-platform Go binary under the Apache-2.0 license. There is no Anonmyz cloud service, account, telemetry pipeline, database, or runtime dependency.

## Judge in two minutes

```bash
go build -trimpath -o anonmyz .
./anonmyz demo --non-interactive
go run ./scripts/verify-codex-fail-closed
```

Repository: https://github.com/3mre0s/ai-firewall
