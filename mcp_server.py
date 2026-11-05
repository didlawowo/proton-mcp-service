#!/usr/bin/env python3
"""Serveur MCP pour ProtonMail via le micro-service proton-service.

Expose en outils MCP : auth (login/2FA), lecture (liste/détail/PJ) et envoi.
URL du service configurable via la variable d'environnement PROTON_SERVICE_URL
(défaut : http://localhost:8080, l'instance locale lancée par `task run`).

Variables : PROTON_USERNAME (utilisateur par défaut de proton_login),
PROTON_WRITE_SECRET (clé d'écriture X-Write-Key, voir README « Write gate »).

Lancement : `uv run python mcp_server.py` (stdio) — voir README pour la
configuration d'un client MCP.
"""

import hmac
import os
import re
import time
from email.message import Message
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

BASE_URL = os.getenv("PROTON_SERVICE_URL", "http://localhost:8080").rstrip("/")
DEFAULT_USERNAME = os.getenv("PROTON_USERNAME", "")
TIMEOUT = 60.0
MAX_FILENAME_BYTES = 200
WINDOWS_DEVICE_NAME = re.compile(r"(con|prn|aux|nul|com\d|lpt\d)(\..*)?", re.IGNORECASE)

mcp = FastMCP(
    "proton-service",
    # Desactive la protection anti DNS-rebinding du SDK MCP : sinon le Host
    # externe (celui de l'ingress/gateway qui expose le MCP en HTTP) est rejete
    # avec "421 Invalid Host header". A ne desactiver que si le service est
    # protege en amont (token MCP_AUTH_TOKEN et/ou reseau de confiance).
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


def _client() -> httpx.Client:
    key = os.getenv("PROTON_API_KEY", "")
    headers = {"X-API-Key": key} if key else {}
    return httpx.Client(base_url=BASE_URL, timeout=TIMEOUT, headers=headers)


def _now() -> int:
    """Timestamp Unix courant en secondes (isolé pour les tests)."""
    return int(time.time())


def _check(r: httpx.Response) -> None:
    """Lève une erreur lisible si non authentifié, sinon raise_for_status."""
    if r.status_code == 401:
        raise RuntimeError(
            "Accès refusé : vérifie PROTON_API_KEY ou appelle proton_login(username) "
            "puis proton_submit_2fa(code)."
        )
    r.raise_for_status()


def _write_headers() -> dict:
    """En-tete X-Write-Key pour les actions d'ecriture (send/create/delete).

    La cle n'est jamais exposee comme parametre des outils MCP : elle provient
    uniquement de la variable d'environnement PROTON_WRITE_SECRET du processus
    MCP. Sans elle, les ecritures sont refusees par le write-gate du service
    (reponse 401/403 documentee par _parse_write_response).
    """
    secret = os.getenv("PROTON_WRITE_SECRET", "")
    if not secret:
        return {}
    return {"X-Write-Key": secret}


def _parse_write_response(r: httpx.Response) -> dict:
    """Normalise la réponse d'une action d'écriture (send/create/delete).

    Renvoie le corps JSON (dict) enrichi du `http_status`, et d'un `error_hint`
    si le write-gate a refusé la requête (401/403).
    """
    data: dict = {}
    try:
        parsed = r.json()
        if isinstance(parsed, dict):
            data = parsed
    except ValueError:
        data = {"status": "error", "body": r.text[:300]}
    data["http_status"] = r.status_code
    if r.status_code in (401, 403):
        data["error_hint"] = (
            "Écriture refusée : vérifier PROTON_API_KEY, la session Proton "
            "et la configuration du write-gate côté service."
        )
    return data


@mcp.tool()
def proton_auth_status() -> dict:
    """État d'authentification du service ProtonMail (health + session)."""
    with _client() as c:
        health = c.get("/health").json()
        return {"base_url": BASE_URL, **health}


@mcp.tool()
def proton_login(username: str = DEFAULT_USERNAME, hv_token: str = "") -> dict:
    """Étape 1 de connexion ProtonMail (mot de passe géré côté serveur).

    Renvoie status='2fa_required' s'il faut ensuite appeler proton_submit_2fa.
    Si la réponse contient `hv_required: true`, Proton demande une vérification
    humaine (CAPTCHA) : ouvrir `verify_url`, résoudre le CAPTCHA, puis rappeler
    proton_login avec le token obtenu dans `hv_token`.
    """
    payload = {"username": username}
    if hv_token:
        payload["hv_token"] = hv_token
    with _client() as c:
        r = c.post("/api/v1/auth/login", json=payload)
        try:
            return r.json()
        except ValueError:
            return {
                "status": "error",
                "http_status": r.status_code,
                "body": r.text[:200],
            }


@mcp.tool()
def proton_submit_2fa(code: str) -> dict:
    """Étape 2 : valide le code TOTP (2FA) après proton_login."""
    with _client() as c:
        r = c.post("/api/v1/auth/2fa", json={"code": code})
        try:
            return r.json()
        except ValueError:
            return {
                "status": "error",
                "http_status": r.status_code,
                "body": r.text[:200],
            }


@mcp.tool()
def proton_list_messages(
    subject: str = "",
    label: str = "5",
    has_attachments: bool = False,
    address: str = "",
    limit: int = 25,
) -> list[dict]:
    """Liste/recherche des emails. label='5' = All Mail, '0' = Inbox.

    `subject` filtre par sujet (sous-chaîne). `address` restreint aux messages
    reçus sur une adresse précise du compte (email ou AddressID ; un compte
    Proton peut avoir plusieurs adresses — voir proton_list_addresses). Renvoie
    les métadonnées (id, date, expéditeur, adresse de réception, sujet, nb de
    PJ) — utiliser proton_get_message pour le contenu.
    """
    params: dict = {"limit": str(limit), "label": label}
    if has_attachments:
        params["has_attachments"] = "true"
    if subject:
        params["subject"] = subject
    if address:
        # "@" présent => email à résoudre côté service ; sinon AddressID opaque.
        params["address" if "@" in address else "address_id"] = address
    with _client() as c:
        r = c.get("/api/v1/messages", params=params)
        _check(r)
        msgs = r.json().get("messages", [])
    return [
        {
            "id": m.get("id"),
            "date": m.get("time"),
            "from": m.get("sender_email"),
            "to": m.get("to", []),
            "address_id": m.get("address_id"),
            "subject": m.get("subject"),
            "num_attachments": m.get("num_attachments"),
        }
        for m in msgs
    ]


@mcp.tool()
def proton_get_message(message_id: str) -> dict:
    """Détail d'un email avec son corps déchiffré et la liste des pièces jointes."""
    with _client() as c:
        r = c.get(f"/api/v1/messages/{message_id}")
        _check(r)
        m = r.json()
    return {
        "id": m.get("id"),
        "subject": m.get("subject"),
        "from": m.get("sender_email"),
        "to": m.get("to", []),
        "cc": m.get("cc", []),
        "address_id": m.get("address_id"),
        "date": m.get("time"),
        "mime_type": m.get("mime_type"),
        "label_ids": m.get("label_ids", []),
        "body": m.get("body"),
        "attachments": [
            {"id": a.get("id"), "name": a.get("name"), "size": a.get("size")}
            for a in m.get("attachments", [])
        ],
    }


@mcp.tool()
def proton_list_labels() -> list[dict]:
    """Liste les labels et dossiers du compte Proton (système + personnalisés).

    Chaque entrée : id (LabelID utilisable dans proton_list_messages(label=...)),
    name, type (1=label, 3=dossier, 4=système), path, color, parent_id.
    """
    with _client() as c:
        r = c.get("/api/v1/labels")
        _check(r)
        labels = r.json().get("labels", [])
    return labels


@mcp.tool()
def proton_list_addresses() -> list[dict]:
    """Liste les adresses email du compte Proton (primaire, alias, domaines custom).

    Un même compte Proton peut posséder plusieurs adresses. Chaque entrée : id
    (AddressID), email, status (enabled/disabled/deleting), type (original/alias/
    custom/premium/external), send/receive (bool), order, display_name. Utile pour
    choisir l'expéditeur de proton_send_email(from_addr=...) ou filtrer la lecture
    avec proton_list_messages(address=...).
    """
    with _client() as c:
        r = c.get("/api/v1/addresses")
        _check(r)
        return r.json().get("addresses", [])


def _shorten_filename(name: str) -> str:
    """Tronque en octets, avec une marge pour le suffixe numérique de collision."""
    if len(name.encode()) <= MAX_FILENAME_BYTES:
        return name
    stem, suffix = Path(name).stem, Path(name).suffix
    if len(suffix.encode()) > 16:
        suffix = ""
    room = MAX_FILENAME_BYTES - len(suffix.encode())
    return stem.encode()[:room].decode(errors="ignore") + suffix


def _attachment_filename(content_disposition: str, fallback: str) -> str:
    """Renvoie un nom de fichier nu : le nom d'une PJ est choisi par l'expéditeur.

    Retire tout chemin, les caractères de contrôle et les points de tête, pour
    qu'un email ne puisse ni sortir de dest_dir ni déposer un fichier caché.
    Couvre aussi Windows, où `C:foo` remplacerait dest_dir et `a.txt:b` écrirait
    dans un flux NTFS.
    """
    header = Message()
    header["Content-Disposition"] = content_disposition
    for candidate in (header.get_filename() or "", fallback):
        # Les deux séparateurs : la plateforme de l'expéditeur est inconnue.
        name = candidate.replace("\\", "/").rsplit("/", 1)[-1]
        name = "".join(ch for ch in name if ch.isprintable()).strip(". ")
        name = re.sub(r'[<>:"|?*]', "_", name)
        if name:
            return _shorten_filename(
                f"_{name}" if WINDOWS_DEVICE_NAME.fullmatch(name) else name
            )
    return "attachment"


def _write_new_file(dest: Path, name: str, content: bytes) -> Path:
    """Écrit sans jamais remplacer un fichier ni suivre un lien symbolique."""
    stem, suffix = Path(name).stem, Path(name).suffix
    for attempt in range(1000):
        out = dest / (f"{stem}-{attempt}{suffix}" if attempt else name)
        try:
            with out.open("xb") as stream:
                stream.write(content)
        except FileExistsError:
            continue
        return out
    raise RuntimeError(f"Trop de fichiers existants pour {name} dans {dest}")


@mcp.tool()
def proton_download_attachment(
    message_id: str, attachment_id: str, dest_dir: str = "."
) -> dict:
    """Télécharge une pièce jointe (déchiffrée) dans dest_dir. Renvoie le chemin.

    Un fichier existant n'est jamais remplacé : un suffixe numérique est ajouté.
    """
    with _client() as c:
        r = c.get(f"/api/v1/messages/{message_id}/attachments/{attachment_id}")
        _check(r)
        content = r.content
        name = _attachment_filename(
            r.headers.get("content-disposition", ""), attachment_id
        )
    dest = Path(dest_dir).expanduser()
    dest.mkdir(parents=True, exist_ok=True)
    out = _write_new_file(dest, name, content)
    return {"path": str(out.resolve()), "size": len(content)}


def _normalize_attachments(attachments: list[dict] | None) -> list[dict] | None:
    """Normalise la liste de PJ pour l'API : content_base64 -> content."""
    if not attachments:
        return None
    normalized = []
    for att in attachments:
        entry = {"filename": att.get("filename", "")}
        content = att.get("content_base64") or att.get("content", "")
        if content:
            entry["content"] = content
        if att.get("mime_type"):
            entry["mime_type"] = att["mime_type"]
        normalized.append(entry)
    return normalized


def _build_send_payload(
    to: list[str],
    subject: str,
    body: str,
    cc: list[str] | None,
    html: str | None,
    attachments: list[dict] | None,
    in_reply_to: str = "",
    action: str = "",
    from_addr: str = "",
) -> dict:
    """Construit le payload POST /api/v1/messages/send."""
    payload: dict = {"to": to, "subject": subject, "body": body, "cc": cc or []}
    if from_addr:
        payload["from"] = from_addr
    if html:
        payload["html"] = html
    norm = _normalize_attachments(attachments)
    if norm:
        payload["attachments"] = norm
    if in_reply_to:
        payload["in_reply_to"] = in_reply_to
    if action:
        payload["action"] = action
    return payload


@mcp.tool()
def proton_send_email(
    to: list[str],
    subject: str,
    body: str,
    cc: list[str] | None = None,
    html: str | None = None,
    attachments: list[dict] | None = None,
    in_reply_to: str = "",
    action: str = "",
    from_addr: str = "",
) -> dict:
    """Envoie un email. Internes chiffrés, externes en clair.

    `to`/`cc` : listes d'adresses. `body` : texte brut ; `html` : corps HTML
    (utilisé à la place du texte brut si fourni). `attachments` : liste de dicts
    `{"filename": ..., "content_base64": ..., "mime_type": ...}`.

    `from_addr` : adresse d'envoi optionnelle — doit être une adresse active du
    compte Proton. Vide = adresse primaire.

    `in_reply_to` : ID interne Proton du message auquel répondre ou que
    transférer (le champ `id` renvoyé par `proton_list_messages` /
    `proton_get_message`). Omet ce paramètre pour un nouveau message.

    `action` : lien avec le message parent — `"reply"` (répondre à
    l'expéditeur), `"reply_all"` (répondre à tous), `"forward"` (transférer).
    Ignorée si `in_reply_to` est vide.

    Action d'écriture — vérifier le contenu avant.
    """
    payload = _build_send_payload(
        to, subject, body, cc, html, attachments, in_reply_to, action, from_addr
    )
    with _client() as c:
        r = c.post("/api/v1/messages/send", json=payload, headers=_write_headers())
        return _parse_write_response(r)


@mcp.tool()
def proton_list_calendars() -> list[dict]:
    """Liste les calendriers ProtonMail de l'utilisateur.

    `type` est une valeur technique renvoyée telle quelle par Proton (0 est
    généralement personnel, 1 abonné/partagé, mais d'autres valeurs comme 2
    existent pour des calendriers système). C'est un indice, pas une catégorie
    métier fiable, quand `name`/`description` sont vides côté compte Proton.
    """
    with _client() as c:
        r = c.get("/api/v1/calendars")
        _check(r)
        cals = r.json().get("calendars", [])
    return [
        {
            "id": cal.get("id"),
            "name": cal.get("name"),
            "description": cal.get("description"),
            "color": cal.get("color"),
            "type": cal.get("type"),
        }
        for cal in cals
    ]


@mcp.tool()
def proton_list_events(
    calendar_id: str,
    from_time: int | None = None,
    to_time: int | None = None,
    timezone: str | None = None,
) -> list[dict]:
    """Liste les événements d'un calendrier (VEVENT déchiffrés), triés par date.

    `calendar_id` : l'id d'un calendrier renvoyé par proton_list_calendars.

    `from_time`/`to_time` : bornes en timestamp Unix (secondes), transmises
    uniquement lorsqu'elles sont fournies explicitement. Sans borne, le MCP
    laisse la route REST appliquer son comportement par défaut. Cela évite le
    `from=<epoch courant>` implicite qui déclenchait un 500 (#48).

    `timezone` : fuseau IANA de l'utilisateur (ex. "Europe/Paris"), utilisé par
    Proton pour placer les événements sur la journée entière dans la fenêtre.
    Défaut UTC.

    `start_time`/`end_time` sont en timestamp Unix ; `start_timezone`/
    `end_timezone` donnent le fuseau IANA (ex. "Europe/Paris") associé.
    """
    if from_time is not None and to_time is not None and 0 < to_time < from_time:
        raise ValueError("to_time est antérieur à from_time")
    params: dict = {}
    if from_time is not None:
        params["from"] = from_time
    if to_time is not None:
        params["to"] = to_time
    if timezone:
        params["timezone"] = timezone
    with _client() as c:
        r = c.get(f"/api/v1/calendars/{calendar_id}/events", params=params)
        _check(r)
        events = r.json().get("events", [])
    return [
        {
            "id": e.get("id"),
            "uid": e.get("uid"),
            "start_time": e.get("start_time"),
            "start_timezone": e.get("start_timezone"),
            "end_time": e.get("end_time"),
            "end_timezone": e.get("end_timezone"),
            "full_day": e.get("full_day"),
            "vevent": e.get("vevent"),
        }
        for e in events
    ]


@mcp.tool()
def proton_create_event(
    calendar_id: str,
    summary: str,
    start_time: int,
    end_time: int,
    description: str = "",
    location: str = "",
    timezone: str = "",
    full_day: bool = False,
) -> dict:
    """Crée un événement (chiffré de bout en bout) dans un calendrier.

    `calendar_id` : un id de `proton_list_calendars`. `start_time`/`end_time` :
    timestamps Unix. `timezone` : nom IANA optionnel (ex: "Europe/Paris"),
    sinon UTC. `full_day` : événement journée entière.

    Action d'écriture — vérifier le contenu avant.
    """
    payload = {
        "summary": summary,
        "description": description,
        "location": location,
        "start_time": start_time,
        "end_time": end_time,
        "timezone": timezone,
        "full_day": full_day,
    }
    with _client() as c:
        r = c.post(
            f"/api/v1/calendars/{calendar_id}/events",
            json=payload,
            headers=_write_headers(),
        )
        return _parse_write_response(r)


@mcp.tool()
def proton_delete_event(calendar_id: str, event_id: str) -> dict:
    """Supprime un événement d'un calendrier.

    `calendar_id` : id du calendrier ; `event_id` : id d'un événement renvoyé
    par `proton_list_events`.

    Action d'écriture — vérifier le contenu avant.
    """
    with _client() as c:
        r = c.delete(
            f"/api/v1/calendars/{calendar_id}/events/{event_id}",
            headers=_write_headers(),
        )
        return _parse_write_response(r)


def _bearer_matches(authorization: str, token: str) -> bool:
    """Compare en temps constant. En octets : les str non ASCII lèveraient TypeError."""
    return hmac.compare_digest(authorization.encode(), f"Bearer {token}".encode())


def _run_http() -> None:
    """Sert le MCP en HTTP (streamable-http) avec auth par token + /healthz.

    Variables : MCP_HOST (0.0.0.0), MCP_PORT (9090), MCP_AUTH_TOKEN (si vide :
    pas d'auth — à n'utiliser qu'en réseau isolé).
    """
    import uvicorn
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse
    from starlette.routing import Route

    token = os.getenv("MCP_AUTH_TOKEN", "")
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "9090"))

    app = mcp.streamable_http_app()

    async def healthz(_req: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    app.router.routes.append(Route("/healthz", healthz, methods=["GET"]))

    if token:

        class _AuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                if request.url.path == "/healthz":
                    return await call_next(request)
                if not _bearer_matches(request.headers.get("authorization", ""), token):
                    return JSONResponse({"error": "unauthorized"}, status_code=401)
                return await call_next(request)

        app.add_middleware(_AuthMiddleware)

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    if os.getenv("MCP_TRANSPORT", "stdio").lower() == "http":
        _run_http()
    else:
        mcp.run()
