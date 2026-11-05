# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities via [GitHub Security Advisories](https://github.com/didlawowo/proton-mcp-service/security/advisories/new)
for this repository. Do not open a public issue for security reports.

We aim to acknowledge reports within 72 hours.

## Security model

The service stores a **live Proton session** (access/refresh tokens and the
account's decrypted mail/calendar data path) on disk under `DATA_DIR`. Treat
that directory as sensitive material:

- Keep `DATA_DIR` on access-restricted storage (Kubernetes: PVC, not hostPath).
- The REST API requires `PROTON_API_KEY` in the `X-API-Key` header. The
  unauthenticated health probe returns only service status. Use TLS or a trusted
  network to protect the key in transit. Setting `PROTON_ALLOW_UNAUTHENTICATED=true`
  explicitly disables API authentication and permits anyone with network access
  to read the account; use it only on a trusted, access-restricted network.
- The MCP HTTP transport can require a bearer token (`MCP_AUTH_TOKEN`); when
  the variable is empty there is no auth at all — only use that on an isolated
  network.
- Mutating operations (send email, calendar write) are gated by a second
  secret (`PROTON_WRITE_SECRET`, presented via the `X-Write-Key` header).
  By default, writes are disabled when it is unset (fail-closed). Setting
  `PROTON_ALLOW_WRITES_WITHOUT_KEY=true` explicitly bypasses this gate, even
  if a secret is configured: anyone who can reach the API can then write.
  Use this option only on a trusted, access-restricted network.
- Do not commit `.env`, `.envrc` or `data/` — they are gitignored for a reason.
