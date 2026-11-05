"""Tests du payload MCP d'envoi d'email (html + pièces jointes).

Dépendances requises : mcp + httpx (installées dans Dockerfile.mcp).
Si absentes, les tests sont sautés.
"""

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("mcp")

import httpx

import mcp_server
from mcp_server import _build_send_payload, _normalize_attachments, _write_headers, mcp


def test_calendar_tools_registered():
    tools = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "proton_list_calendars" in tools
    assert "proton_list_events" in tools
    assert "proton_send_email" in tools
    assert "proton_create_event" in tools
    assert "proton_delete_event" in tools


def test_address_tools_registered():
    tools = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "proton_list_addresses" in tools


def test_list_messages_accepts_address_filter():
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    props = tools["proton_list_messages"].inputSchema.get("properties", {})
    assert "address" in props, "proton_list_messages doit exposer un filtre par adresse"


def test_list_events_accepts_time_range_filter():
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    props = tools["proton_list_events"].inputSchema.get("properties", {})
    assert "from_time" in props, "proton_list_events doit exposer un filtre from_time"
    assert "to_time" in props, "proton_list_events doit exposer un filtre to_time"
    assert "timezone" in props, "proton_list_events doit exposer un fuseau"


def _capture_events_request(monkeypatch) -> dict:
    """Remplace le client HTTP pour inspecter la requête envoyée au service."""
    import httpx

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"events": []})

    monkeypatch.setattr(
        mcp_server,
        "_client",
        lambda: httpx.Client(
            base_url="http://proton.test", transport=httpx.MockTransport(handler)
        ),
    )
    return captured


def test_list_events_does_not_inject_from_by_default(monkeypatch):
    captured = _capture_events_request(monkeypatch)
    assert mcp_server.proton_list_events("cal1") == []
    assert captured["params"] == {}


def test_list_events_forwards_explicit_bounds_and_timezone(monkeypatch):
    captured = _capture_events_request(monkeypatch)
    mcp_server.proton_list_events(
        "cal1", from_time=0, to_time=1_800_000_000, timezone="Europe/Paris"
    )
    assert captured["params"] == {
        "from": "0",
        "to": "1800000000",
        "timezone": "Europe/Paris",
    }


def test_list_events_accepts_to_without_implicit_from(monkeypatch):
    captured = _capture_events_request(monkeypatch)
    mcp_server.proton_list_events("cal1", to_time=1_800_000_000)
    assert captured["params"] == {"to": "1800000000"}


def test_list_events_rejects_explicit_end_before_explicit_start(monkeypatch):
    captured = _capture_events_request(monkeypatch)
    with pytest.raises(ValueError):
        mcp_server.proton_list_events(
            "cal1", from_time=1_700_000_000, to_time=1_600_000_000
        )
    assert captured == {}


def test_internal_write_header_comes_only_from_environment(monkeypatch):
    monkeypatch.delenv("PROTON_WRITE_SECRET", raising=False)
    assert _write_headers() == {}
    monkeypatch.setenv("PROTON_WRITE_SECRET", "s3cret")
    assert _write_headers() == {"X-Write-Key": "s3cret"}


def test_write_tools_do_not_expose_write_key():
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    for name in ("proton_send_email", "proton_create_event", "proton_delete_event"):
        props = tools[name].inputSchema.get("properties", {})
        assert "write_key" not in props, f"{name} ne doit pas exposer write_key"


def test_payload_plain():
    payload = _build_send_payload(
        to=["a@proton.me"],
        subject="Sujet",
        body="Texte brut",
        cc=None,
        html=None,
        attachments=None,
    )
    assert payload == {
        "to": ["a@proton.me"],
        "subject": "Sujet",
        "body": "Texte brut",
        "cc": [],
    }


def test_payload_html():
    payload = _build_send_payload(
        to=["a@proton.me"],
        subject="Sujet",
        body="Texte brut",
        cc=None,
        html="<h1>Bonjour</h1>",
        attachments=None,
    )
    assert payload["html"] == "<h1>Bonjour</h1>"


def test_payload_attachments_maps_content_base64():
    attachments = [
        {
            "filename": "r.xlsx",
            "content_base64": "AAA=",
            "mime_type": "application/vnd.ms-excel",
        }
    ]
    payload = _build_send_payload(
        to=["a@proton.me"],
        subject="Sujet",
        body="Texte",
        cc=["b@proton.me"],
        html=None,
        attachments=attachments,
    )
    assert payload["attachments"] == [
        {
            "filename": "r.xlsx",
            "content": "AAA=",
            "mime_type": "application/vnd.ms-excel",
        }
    ]
    assert payload["cc"] == ["b@proton.me"]


def test_payload_threading_reply() -> None:
    """in_reply_to + action sont propagés dans le payload (reply dans le fil)."""
    payload = _build_send_payload(
        to=["b@proton.me"],
        subject="Re: Facture",
        body="Suite",
        cc=None,
        html=None,
        attachments=None,
        in_reply_to="msg-abc123",
        action="reply",
    )
    assert payload["in_reply_to"] == "msg-abc123"
    assert payload["action"] == "reply"


def test_payload_threading_omitted_by_default() -> None:
    """Sans in_reply_to, aucun champ threading dans le payload (nouveau mail)."""
    payload = _build_send_payload(
        to=["b@proton.me"],
        subject="Bonjour",
        body="Texte",
        cc=None,
        html=None,
        attachments=None,
    )
    assert "in_reply_to" not in payload
    assert "action" not in payload


def _stub_attachment(monkeypatch, disposition: str, content: bytes = b"data") -> None:
    response = httpx.Response(200, content=content)
    response.headers["content-disposition"] = disposition
    transport = httpx.MockTransport(lambda _request: response)
    monkeypatch.setattr(
        mcp_server,
        "_client",
        lambda: httpx.Client(base_url="http://service", transport=transport),
    )


@pytest.mark.parametrize(
    ("disposition", "expected"),
    [
        ('attachment; filename="invoice.pdf"', "invoice.pdf"),
        ("attachment; filename*=utf-8''rapport%20%C3%A9t%C3%A9.pdf", "rapport été.pdf"),
        ('attachment; filename="../../escaped.txt"', "escaped.txt"),
        ('attachment; filename="/etc/cron.d/job"', "job"),
        ('attachment; filename="..\\\\..\\\\escaped.txt"', "escaped.txt"),
        ("attachment; filename*=utf-8''..%2F..%2Fescaped.txt", "escaped.txt"),
        ('attachment; filename=".bashrc"', "bashrc"),
        ('attachment; filename=".."', "attachment-id"),
        ('attachment; filename="dir/"', "attachment-id"),
        ('attachment; filename="a\tb.txt"', "ab.txt"),
        ("attachment", "attachment-id"),
        ("", "attachment-id"),
    ],
)
def test_attachment_filename_is_a_bare_name(disposition, expected):
    assert mcp_server._attachment_filename(disposition, "attachment-id") == expected


def test_attachment_filename_sanitizes_the_fallback():
    assert mcp_server._attachment_filename("", "../../escaped") == "escaped"
    assert mcp_server._attachment_filename("", "..") == "attachment"


@pytest.mark.parametrize(
    "name", ["../../escaped.txt", "/tmp/proton-absolute-escape.txt"]
)
def test_download_attachment_stays_in_dest_dir(monkeypatch, tmp_path, name):
    dest = tmp_path / "inbox" / "downloads"
    _stub_attachment(monkeypatch, f'attachment; filename="{name}"')

    result = mcp_server.proton_download_attachment("msg", "att", str(dest))

    written = Path(result["path"])
    assert written.parent == dest.resolve()
    assert written.read_bytes() == b"data"
    assert not (tmp_path / "escaped.txt").exists()


def test_download_attachment_never_replaces_a_file(monkeypatch, tmp_path):
    existing = tmp_path / "report.pdf"
    existing.write_bytes(b"original")
    _stub_attachment(monkeypatch, 'attachment; filename="report.pdf"')

    result = mcp_server.proton_download_attachment("msg", "att", str(tmp_path))

    assert existing.read_bytes() == b"original"
    assert Path(result["path"]).name == "report-1.pdf"


def test_download_attachment_does_not_follow_a_symlink(monkeypatch, tmp_path):
    target = tmp_path / "authorized_keys"
    target.write_bytes(b"original")
    dest = tmp_path / "downloads"
    dest.mkdir()
    (dest / "keys").symlink_to(target)
    _stub_attachment(monkeypatch, 'attachment; filename="keys"')

    result = mcp_server.proton_download_attachment("msg", "att", str(dest))

    assert target.read_bytes() == b"original"
    assert Path(result["path"]).parent == dest.resolve()


@pytest.mark.parametrize(
    ("disposition", "expected"),
    [
        ('attachment; filename="C:job"', "C_job"),
        ('attachment; filename="a.txt:stream"', "a.txt_stream"),
        ('attachment; filename="CON"', "_CON"),
        ('attachment; filename="nul.txt"', "_nul.txt"),
        ('attachment; filename="report."', "report"),
    ],
)
def test_attachment_filename_is_safe_on_windows(disposition, expected):
    assert mcp_server._attachment_filename(disposition, "attachment-id") == expected


def test_attachment_filename_is_shortened_for_the_filesystem():
    name = mcp_server._attachment_filename(
        f'attachment; filename="{"é" * 300}.pdf"', "attachment-id"
    )
    assert name.endswith(".pdf")
    assert len(name.encode()) <= mcp_server.MAX_FILENAME_BYTES


def test_download_attachment_keeps_a_very_long_name(monkeypatch, tmp_path):
    _stub_attachment(monkeypatch, f'attachment; filename="{"a" * 300}.txt"')

    result = mcp_server.proton_download_attachment("msg", "att", str(tmp_path))

    assert Path(result["path"]).read_bytes() == b"data"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer secret", True),
        ("Bearer wrong", False),
        ("secret", False),
        ("", False),
        ("Bearer sécret", False),
    ],
)
def test_bearer_matches(header, expected):
    assert mcp_server._bearer_matches(header, "secret") is expected


def test_normalize_attachments_none_and_empty():
    assert _normalize_attachments(None) is None
    assert _normalize_attachments([]) is None


def test_normalize_attachments_accepts_content():
    assert _normalize_attachments([{"filename": "a.txt", "content": "QQ=="}]) == [
        {"filename": "a.txt", "content": "QQ=="}
    ]


def test_api_key_forwarded_to_service(monkeypatch):
    monkeypatch.setenv("PROTON_API_KEY", "test-api-key")
    with mcp_server._client() as client:
        assert client.headers["X-API-Key"] == "test-api-key"
    monkeypatch.delenv("PROTON_API_KEY")
    with mcp_server._client() as client:
        assert "X-API-Key" not in client.headers
