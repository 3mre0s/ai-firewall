# Security Policy — Local AI Firewall

We take the security of your sensitive data, API credentials, and development environments seriously. Because Local AI Firewall acts as a security gateway between your systems and public cloud APIs, this document defines our security posture, vulnerability reporting procedures, and architectural guarantees.

## Supported Versions

Only the latest release receives security patches. Since the firewall is distributed as a lightweight, single-binary application, we request all users to immediately update to the latest tag if a vulnerability is patched.

| Version | Supported |
| --- | --- |
| v1.x | :white_check_mark: Yes |
| < v1.0 | :x: No |

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability (such as a pattern bypass, memory leak, or authorization issue), report it confidentially:

1. **Email**: Send a detailed report to `security@localai-firewall.internal` (replace with your organization's security contact if deployed internally).
2. **Encrypted Communications**: If your report contains sensitive reproduction steps, request our PGP key before sending.
3. **Response Timeline**:
   - **Acknowledgment**: Within 24 hours.
   - **Triage & Mitigation**: Within 3 business days.
   - **Fix & Coordinated Disclosure**: Within 7 business days.

## Architectural Security Guarantees

Local AI Firewall provides the following structural guarantees by design:

*   **Zero-Disk Footprint**: The central `Vault` (kasası) resides **exclusively in-memory**. At no point are masked text values, original secrets, or mapping labels written to persistent storage (SSD/HDD) or swap space (where preventable).
*   **Zero-Leak Logging**: Under no `LOG_LEVEL` (including `debug`) will the `FORWARD_API_KEY` or raw request/response text payloads be written to `stdout`, `stderr`, or system logs.
*   **Graceful Memory Wipe**: On receiving OS signals (`SIGINT` / `SIGTERM`), the startup loop intercepts the shutdown and calls `v.Reset()`. This explicitly clears the internal Go map references and forces garbage collection, leaving no sensitive buffers in memory before process exit.
*   **Cryptographically Random Placeholders**: The generated labels use hex-encoded hashes of the salt, timestamp, and value, ensuring that placeholders cannot be used upstream to brute-force or infer the shape of the original secrets.
*   **Single-Purpose Scope**: The binary contains no dependencies outside the Go standard library (other than internal package wiring), drastically minimizing the supply-chain attack surface.
