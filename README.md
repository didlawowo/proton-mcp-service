# proton-service

**Proton Mail + Calendar as a REST API — plus an MCP server for AI agents.**

A small self-hosted Go micro-service that authenticates against Proton's API
(SRP login, TOTP 2FA, CAPTCHA/human-verification handling), keeps the session
alive, and exposes decrypted mail and calendar data over a clean REST API.
A Python MCP server (`mcp_server.py`) sits on top of that API so any
MCP-capable agent (Claude Desktop, OpenCode, ...) can read, search, send mail
and manage calendar events.

It is built around
[go-proton-api](https://github.com/ProtonMail/go-proton-api) and
[go-mime](https://github.com/ProtonMail/go-mime).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> This repository is a published snapshot: each release arrives as a single commit,
> and no CI runs here. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Why this project

Most Proton MCP servers sit on top of
[Proton Mail Bridge](https://proton.me/mail/bridge): one more app to keep running
and signed in, which only exposes mail over IMAP and SMTP. proton-service is
built to run as a shared service instead, on a server or in a cluster.

- **Ready for Kubernetes.** A Helm chart, multi-arch Docker images, and an MCP
  server over streamable HTTP, so several agents can share one deployment.
- **No Bridge.** The service talks to Proton's client API directly.
- **Mail and calendar in one service.** One session and one API, including
  end-to-end encrypted calendar reads and writes.
- **A plain REST API underneath.** Anything that speaks HTTP can use it, not only
  MCP clients.

Other projects may fit you better.
[proton-cli](https://github.com/roman-16/proton-cli) covers more Proton apps and
more calendar features in a single binary, and its fork
[proton-mcp](https://github.com/YellowUmbrellaDev/proton-mcp) exposes those
commands over MCP.
[proton-cal](https://github.com/cheeseandcereal/proton-cal) focuses on the
calendar. Here, creating recurring events and editing events are not implemented
yet.

## What it can do

- **Auth**: SRP login, TOTP 2FA, one-shot CAPTCHA / human-verification flow,
  scope elevation, session persisted to disk (survives restarts, auto refresh).
- **Mail**: list/search (label, subject, attachments, per-address), full
  message with decrypted body, decrypted attachment download, labels, addresses.
- **Send**: text or HTML body, attachments, reply / reply-all / forward with
  proper thread linkage, multiple sender addresses.
- **Calendar**: list calendars, list decrypted `VEVENT`s (time range + IANA
  timezone), create and delete events (encrypted end-to-end).
- **MCP server**: all of the above as agent tools, over stdio or streamable
  HTTP (with bearer-token auth).
- **Write gate**: mutating routes (send, event create/delete) require a second
  secret by default, and are disabled when it is not configured. An explicit
  opt-out allows writes without a key on trusted networks.

> [!WARNING]
> **Proton's mail/calendar client API is private, not public.** This service
> speaks the same API the official clients use. Expect occasional breakage
> when Proton changes it, and read Proton's terms of service before running
> this against your account.

## Security model — read before exposing anything

- The REST API requires `X-API-Key` on every route except the minimal health
  probe. Use TLS or a trusted network to protect the key in transit. Explicitly
  setting `PROTON_ALLOW_UNAUTHENTICATED=true` disables this protection.
- By default, mutating routes need `X-Write-Key` to match `PROTON_WRITE_SECRET`;
  an unset secret disables writes. `PROTON_ALLOW_WRITES_WITHOUT_KEY=true`
  bypasses the gate even when a secret is set: use it only on a trusted,
  access-restricted network.
- The MCP HTTP transport supports `MCP_AUTH_TOKEN` (bearer). Empty = no auth.
- `DATA_DIR` holds a live Proton session — treat it like a password.

See [SECURITY.md](SECURITY.md) for the full model and vulnerability reporting.

## Architecture

```
┌────────────────────┐        ┌──────────────────────────┐      Proton API
│  MCP agent         │ stdio  │ mcp_server.py (Python)   │      (private,
│ (Claude, OpenCode) ├───────►│  FastMCP + httpx client  │       SRP/2FA)
└────────────────────┘        └────────────┬─────────────┘       ▲
                                           │ HTTP (REST)         │
                                   ┌───────▼───────────┐    ┌────┴─────┐
                                   │ proton-service    ├────► │  api.   │
                                   │ (Go, :8080)       │    │  proton  │
                                   │ session.json on   │    └──────────┘
                                   │ DATA_DIR volume   │
                                   └───────────────────┘
```

| Module | Role |
|---|---|
| `cmd/server` | entrypoint, env config, HTTP server |
| `pkg/api` | REST handlers + router (swagger UI at `/swagger/index.html`) |
| `pkg/proton` | Proton API client: auth, session restore/refresh, mail read/send, calendar read/write, scope elevation |
| `pkg/session` | JSON session token store (`session.json`, file permissions `0600`; no encryption at rest) |
| `mcp_server.py` | MCP tool layer over the REST API (stdio or HTTP) |
| `helm/proton-service` | Kubernetes/Helm chart (Deployment, PVC, optional Gateway API / Ingress, optional MCP deployment) |

## Getting started (Docker, ~5 minutes)

### Prerequisites

| Requirement | Notes |
|---|---|
| Proton Mail account | paid plan required for calendar access via Proton's API |
| TOTP 2FA enabled | strongly recommended; the login flow asks for it |
| Docker (or Go 1.26) | multi-arch images: `linux/amd64`, `linux/arm64` |
| [uv](https://docs.astral.sh/uv/) | only for the MCP server |

### Run

Create a local, gitignored `.env` file containing `PROTON_PASSWORD` and
`PROTON_API_KEY` and `PROTON_WRITE_SECRET` (use separate random keys). Keep the write key
for clients that need to send mail or modify the calendar.

```bash
docker volume create proton-service-data
docker run -d --name proton-service --env-file=.env -e PROTON_APP_VERSION=Other -v proton-service-data:/data -p 127.0.0.1:8080:8080 ghcr.io/didlawowo/proton-service:latest
```

> `--env-file` keeps secrets out of shell history; container environment values
> remain visible to users with access to Docker. The named volume is initialized
> with permissions for the container's non-root user. The `-p 127.0.0.1:8080:8080` binding restricts access to the local machine.

### Verify + first use

Load `PROTON_API_KEY` into your shell securely before running these commands.

```bash
curl -s localhost:8080/health
curl -s localhost:8080/api/v1/auth/login \
  -H "X-API-Key: $PROTON_API_KEY" -H 'Content-Type: application/json' \
  -d '{"username":"you@proton.me"}'
```

If the response says `"status": "2fa_required"`, submit your TOTP code:

```bash
curl -s localhost:8080/api/v1/auth/2fa \
  -H "X-API-Key: $PROTON_API_KEY" -H 'Content-Type: application/json' -d '{"code":"123456"}'
```

Then read your inbox:

```bash
curl -s -H "X-API-Key: $PROTON_API_KEY" 'localhost:8080/api/v1/messages?label=0&limit=5'
```

If it is empty, wait a second and retry — the first mailbox sync after login
takes a few seconds. If you get `401`, check the API key and Proton login/2FA sequence; the
session is persisted afterwards, so restarts don't need re-auth.

If Proton demands a human check instead, the login response contains
`hv_required: true` and a `verify_url` — see
[Calendar & human verification](#calendar-access-proton_app_version-other-required).

### Run locally without Docker

```bash
task run   # builds then runs with LOG_LEVEL=debug, DATA_DIR=./data, PORT=8080
```

## Configuration

### Service (Go) — environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | HTTP port |
| `DATA_DIR` | `/data` | session + working directory (sensitive) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PROTON_API_KEY` | — | required API key, sent as `X-API-Key` |
| `PROTON_ALLOW_UNAUTHENTICATED` | `false` | explicit API authentication opt-out for trusted networks |
| `PROTON_PASSWORD` | — | your Proton account password |
| `PROTON_APP_VERSION` | `macos-bridge@3.23.1` | `X-Pm-Appversion` value — **product scopes**; use `Other` for calendar |
| `PROTON_WRITE_SECRET` | — | enables mutating routes; clients send it as `X-Write-Key` |
| `PROTON_ALLOW_WRITES_WITHOUT_KEY` | `false` | explicit opt-out of the write gate (trusted networks only) |

### MCP server (Python) — environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PROTON_SERVICE_URL` | `http://localhost:8080` | REST API base URL |
| `PROTON_USERNAME` | — | default `username` for `proton_login` |
| `PROTON_API_KEY` | — | API key sent as `X-API-Key` (never a tool parameter) |
| `PROTON_WRITE_SECRET` | — | sent as `X-Write-Key` on write tools (never a tool parameter) |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_HOST` / `MCP_PORT` | `0.0.0.0` / `9090` | HTTP mode bind |
| `MCP_AUTH_TOKEN` | — | bearer token required by the HTTP transport (empty = no auth) |

## API reference

Live swagger UI: `http://localhost:8080/swagger/index.html`
(machine-readable: [docs/swagger.json](docs/swagger.json)).

| Method | Route | Notes |
|---|---|---|
| `GET` | `/health` | liveness, no auth |
| `POST` | `/api/v1/auth/login` | `{"username"}` (+ `"hv_token"` when CAPTCHA) |
| `POST` | `/api/v1/auth/2fa` | `{"code"}` TOTP |
| `GET` | `/api/v1/auth/status` | session state |
| `POST` | `/api/v1/auth/logout` | drop session |
| `GET` | `/api/v1/messages` | `label`, `subject`, `has_attachments`, `address`/`address_id`, `limit` |
| `GET` | `/api/v1/messages/{id}` | decrypted body + attachment list |
| `GET` | `/api/v1/messages/{id}/attachments/{attachmentId}` | decrypted attachment bytes |
| `GET` | `/api/v1/labels` · `/api/v1/addresses` | folders/labels · account addresses |
| `POST` | `/api/v1/messages/send` | **write**: to/cc/html/attachments/`in_reply_to`/`action`/`from` |
| `GET` | `/api/v1/calendars` | decrypted calendar list |
| `GET` | `/api/v1/calendars/{id}/events` | `from`, `to` (unix), `timezone` (IANA) |
| `POST` | `/api/v1/calendars/{id}/events` | **write**: create encrypted event |
| `DELETE` | `/api/v1/calendars/{id}/events/{eventId}` | **write** |

Write routes return `403` with an explanatory body when the write gate is
closed; set `PROTON_WRITE_SECRET` and send `X-Write-Key`.

## MCP server

### stdio (desktop clients)

```json
{
  "mcpServers": {
    "proton": {
      "command": "uv",
      "args": ["run", "--with", "mcp>=1.2,<2", "--with", "httpx", "python", "mcp_server.py"],
      "env": {
        "PROTON_SERVICE_URL": "http://localhost:8080",
        "PROTON_USERNAME": "you@proton.me",
        "PROTON_WRITE_SECRET": "same-secret-as-the-service"
      }
    }
  }
}
```

### HTTP (multi-client / k8s)

```bash
MCP_TRANSPORT=http MCP_AUTH_TOKEN="$(openssl rand -hex 24)" python mcp_server.py
```

Streamable-HTTP endpoint at `/mcp`, health at `/healthz`, bearer auth enforced
when `MCP_AUTH_TOKEN` is set. Behind a reverse proxy, the SDK's DNS-rebinding
protection is disabled by this server (custom Host headers are the point);
keep the proxy + token in front.

### Tools exposed

`proton_auth_status`, `proton_login`, `proton_submit_2fa`,
`proton_list_messages`, `proton_get_message`, `proton_download_attachment`,
`proton_list_labels`, `proton_list_addresses`, `proton_send_email`,
`proton_list_calendars`, `proton_list_events`, `proton_create_event`,
`proton_delete_event`.

The write key is **never** a tool parameter: the MCP process reads
`PROTON_WRITE_SECRET` from its environment and forwards it as `X-Write-Key`.
Without it, write tools return the service's `401/403` with an `error_hint`.

## Calendar access (`PROTON_APP_VERSION=Other` required)

- The default app version (`macos-bridge`) only holds **mail** scopes —
  calendar routes return `403`. Set `PROTON_APP_VERSION=Other`.
- The first login at that scope triggers a **CAPTCHA / human verification**:
  `proton_login` (or the REST call) returns `hv_required: true` + `verify_url`.
  Open it, solve the CAPTCHA, capture the token the page posts back
  (`HUMAN_VERIFICATION_SUCCESS` message in the browser dev console), then retry
  login with `hv_token`. Afterwards the session is persisted and refreshes
  autonomously — the dance is one-shot.
- Scope elevation (`locked` → full) via `PUT /core/v4/users/unlock` is handled
  automatically.
- Calendar is **not in Proton's public API**; expect occasional breakage.

## Kubernetes (Helm chart)

The chart is published as an OCI chart and installs the API + optional MCP
deployment with a PVC for the session.

```bash
helm install proton-service oci://ghcr.io/didlawowo/charts/proton-service --set env.appVersion=Other
```

Prerequisites the chart does **not** create (bring them beforehand):

- Secret `proton-service-api-key` with key `api-key` (or override `apiAuth.secretName` / `apiAuth.secretKey`). Set `apiAuth.enabled=false` only on a trusted network.
- Secret `proton-service` with key `proton-password` (or override `secret.name`).
- Secret `proton-service-pass` with key `password` (write key; or set
  `writeKey.enabled=false` on a trusted network only).
- Secret holding the MCP bearer token (`mcp.authToken.secretName` / `.key`).

Notable values (see [helm/proton-service/values.yaml](helm/proton-service/values.yaml)):

| Value | Default | Notes |
|---|---|---|
| `image.repository` / `mcp.image.repository` | `ghcr.io/didlawowo/proton-service[-mcp]` | tag defaults to `v<appVersion>` |
| `gateway.enabled` + `parentRefs`/`hostnames` | `false` | Gateway API exposure (CRDs required) |
| `ingress.enabled` | `false` | plain Ingress alternative |
| `persistence.storageClass` | `""` | cluster default |
| `env.appVersion` | `macos-bridge@3.23.1` | set `Other` for calendar |

## Development

```bash
task test          # go test ./...
task lint          # golangci-lint
uvx ruff check mcp_server.py test_mcp_server.py
```

Full setup and how to contribute: [CONTRIBUTING.md](CONTRIBUTING.md).

## License & disclosure

Licensed under the [MIT License](LICENSE). This project is not affiliated with
Proton AG; it uses their private client API at your own risk.
