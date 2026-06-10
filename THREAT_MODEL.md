# Threat Model — Local AI Firewall

This threat model outlines the trust boundaries, threat actors, and security boundaries of the Local AI Firewall. It helps security teams evaluate the product's protection scope and limitations.

## Trust Boundaries

```
                 ┌─────────────────────────────────────────┐
                 │              LOCAL SYSTEM               │
                 │                                         │
  ┌──────────┐   │   ┌──────────────┐   ┌──────────────┐   │        WAN / INTERNET
  │   IDE    │ ──┼─➔ │ AI Firewall  │ ➔ │  Local Vault │   │
  │  Client  │   │   │   (:8080)    │   │ (In-Memory)  │   │
  └──────────┘   │   └──────────────┘   └──────────────┘   │              │
                 │          │                              │              ▼
                 └──────────┼──────────────────────────────┘       ┌──────────────┐
                            │                                      │  AI Upstream │
                            └─────────────────────────────────────➔│ (OpenAI/etc.)│
                                 Masked Text & Upstream Headers    └──────────────┘
```

The trust boundary lies on the **local machine boundary**:
- **Trusted Zone**: Everything running on the local host (IDE, Client apps, AI Firewall proxy, in-memory Vault).
- **Untrusted Zone**: The public internet, WAN, and external cloud AI APIs (OpenAI, Anthropic, Gemini, etc.).

---

## 1. In-Scope Threats (What is Protected)

Local AI Firewall is designed to defend against data exposure to external endpoints.

### Threat 1: Accidental PII / Secret Leakage via Prompts
- **Attack Vector**: A developer copies and pastes log files, environment configurations, or production files into a chatbot or IDE autocomplete tool.
- **Impact**: Corporate secrets, e-mail addresses, database passwords, or private paths are sent to cloud servers, risking compliance violations (GDPR, HIPAA) and data leaks.
- **Mitigation**: The `Masker` automatically intercepts the request, replaces PII/secrets with random labels (`[[EMAIL_XXXXXXXX]]`), and holds the actual secrets in the local Vault. The external provider only sees the sanitised text.

### Threat 2: Credential Disclosure (API Keys / Private Keys)
- **Attack Vector**: Source code containing hardcoded tokens (`ghp_...`, `AKIA...`) or SSH/TLS private keys is sent as context for code explanation.
- **Impact**: Compromised credentials, unauthorized cloud access, or code repository hijacks.
- **Mitigation**: Specific high-accuracy regex patterns automatically identify and vault API tokens and PEM blocks, ensuring they never cross the network boundary.

### Threat 3: Local Environment Path Exposure
- **Attack Vector**: Error logs containing paths like `C:\Users\john_doe\Project\db.json` are sent to the AI.
- **Impact**: Leaking local OS usernames, directory structures, and environment configurations.
- **Mitigation**: Windows and Unix absolute path patterns intercept paths and mask them as `[[WIN_PATH_XXXXXXXX]]` or `[[UNIX_PATH_XXXXXXXX]]`.

---

## 2. Out-of-Scope Threats (What is NOT Protected)

Understanding limitations is critical for enterprise threat modeling.

### Threat 4: Compromised Host OS (Malware / Keyloggers)
- **Attack Vector**: Malware or trojans running on the developer's computer.
- **Impact**: Intercepting keys typed in the IDE, copying clipboard data, or reading configuration files before they reach the proxy.
- **Mitigation**: Outside the firewall's scope. Organizations must enforce endpoint protection (EDR, antivirus) on dev machines.

### Threat 5: Process Memory Dump / Admin Access
- **Attack Vector**: A local malicious user with root/administrator access inspects the running processes or grabs a core dump (`gcore`) of the `ai-firewall` binary.
- **Impact**: Reading the in-memory Vault contents where the original secrets are stored.
- **Mitigation**: Admin-level local compromises cannot be mitigated by user-space applications. Implement system hardening, OS virtualization, or container isolation.

### Threat 6: Upstream AI Provider Compromise
- **Attack Vector**: The third-party AI provider's databases or systems are hacked, exposing chat history.
- **Impact**: Attackers gain access to past prompts.
- **Mitigation**: Since prompts sent upstream only contain masked labels (e.g., `[[SECRET_A1B2C3D4]]`), the attacker only gets sanitised text. They cannot recover the original API keys, e-mails, or paths because those values never existed on the provider's server.

---

## 3. Threat Mitigation Matrix

| Threat ID | Threat Vector | Risk Level | Mitigation Control |
|---|---|---|---|
| **T-01** | Secret leaking to Upstream AI | **Critical** | Pattern-based regex masking and Vault substitution. |
| **T-02** | Eavesdropping on Vault storage | **High** | Vault is **in-memory only** (never written to disk). |
| **T-03** | Residual data post-shutdown | **Medium** | Signal interceptor runs `v.Reset()` on process exit. |
| **T-04** | Unauthorized metrics access | **Low** | Restrict `/metrics` port binding (bind to `127.0.0.1` or firewall it). |
