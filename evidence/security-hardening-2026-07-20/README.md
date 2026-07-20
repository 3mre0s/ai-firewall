# Security hardening verification

Date: 2026-07-20 (Europe/Istanbul)

## Result

The protected Codex model route is fail-closed. The installed Codex CLI first sent its request through a real loopback Anonmyz proxy. The proxy listener and active connection were then terminated during the in-flight request. Codex retried the configured loopback `/responses` URL, exited with an error, and made zero direct model fallback attempts.

The test used a synthetic authentication canary and a local mock upstream. It did not use a real credential or contact an OpenAI model service. HTTP(S) proxy environment variables pointed to a local egress trap during the test.

## Additional controls

- The actual listener address was `127.0.0.1:<dynamic>`, never `0.0.0.0`.
- Authentication header values, OAuth bearer canary, ChatGPT account ID canary, and Cookie canary were absent from captured logs, audit JSON, response bodies, and error output.
- Cookie is not in the proxy request-header allowlist and was not forwarded upstream.

## Reproduction

```powershell
go run .\scripts\verify-codex-fail-closed
go test . -run TestListenLoopbackDynamicAndPortConflict -count=1 -v
go test .\proxy -run TestAuthenticationMetadataNeverAppearsInLogsAuditOrErrors -count=1 -v
```

See the sibling text files for the retained command results. No raw authentication value is retained in this evidence directory.
