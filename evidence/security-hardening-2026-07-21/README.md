# Current Codex Safe Session hardening evidence

Date: 2026-07-21 (Europe/Istanbul)

## Environment

- Codex CLI: `codex-cli 0.145.0-alpha.27`
- Model route: dynamically allocated literal `127.0.0.1` URL
- Apps setting: temporary child-only `features.apps=false`
- External traffic control: HTTP(S) proxy variables pointed to a local egress trap; loopback bypass was limited to `127.0.0.1,localhost`

## Result

The real installed Codex CLI first sent its Responses request through the loopback Anonmyz proxy. The verifier terminated that proxy during the in-flight request. Codex retried only the configured loopback route, exited with an error, and made zero requests through the external-egress trap.

The verifier does not allowlist `chatgpt.com`, OpenAI endpoints, or any other external hostname. Any request that reaches the trap fails verification. The configured model URL must parse to a literal loopback IP address.

## Sanitization

The retained output contains only the Codex CLI version and verifier PASS lines. Child-process output, authentication values, session identifiers, usernames, and local filesystem paths are not retained.

## Reproduction

```powershell
codex --version
go run .\scripts\verify-codex-fail-closed
```
