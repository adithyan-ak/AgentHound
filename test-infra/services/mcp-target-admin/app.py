"""Authored MCP target with an admin surface, for the offline collector harness.

This is a real Model Context Protocol server. It uses the official Python `mcp`
SDK's low-level `Server` plus `StreamableHTTPSessionManager`, mounted on a
Starlette app. It exposes THREE routes on one process, all backed by one shared
in-memory `TOOLS` dict so a mutation on the admin surface is observable on the
next MCP `tools/list`:

  1. `POST /mcp`            real MCP Streamable-HTTP endpoint. Drives
                            `agenthound scan --mcp`, `discover`, and the
                            `campaign --scenario cred-reach` prober (a full MCP
                            client that does initialize + resources/read).
  2. `POST /admin/tools-list`
                            a BARE JSON-RPC 2.0 `tools/list` dispatch. This is
                            what `mcppoison --list-path /admin/tools-list` calls
                            with a plain, sessionless `{"jsonrpc":"2.0",...}`
                            POST (it never does the MCP handshake).
  3. `PUT /admin/tools/{name}`
                            description mutation for `mcppoison`'s update path
                            (`--update-path /admin/tools/{id}`). Body is
                            `{"description": "..."}`.

Credential-gated resource (cred-reach control):
  The `/mcp` endpoint answers `initialize`, `tools/list`, `resources/list`,
  `resources/templates/list`, and `prompts/list` ANONYMOUSLY so `scan`
  enumerates normally. A single resource — GATED_RESOURCE_URI — is gated: an
  outer ASGI wrapper inspects the JSON-RPC body and, for a `resources/read` of
  that exact URI, short-circuits with a real HTTP 401 UNLESS the request carries
  `Authorization: Bearer <token>` whose `sha256hex(token)` equals the
  `GATED_RESOURCE_TOKEN_HASH` env var. A real transport-level 401/403 is
  required: credreach's prober only classifies `ProbeDenied` from an observed
  HTTP 401/403 (an MCP-level JSON-RPC error would classify as indeterminate and
  emit no CREDENTIAL_REACH_VERIFIED edge). The gate matches ONLY method +
  params.uri, so every other method stays anonymous.

No secrets are embedded: the server only holds the sha256 hash of the accepted
bearer token, injected by the harness (which derives it from the same test
secret it exports as AGENTHOUND_CAMPAIGN_CREDENTIAL).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

SERVER_NAME = "mcp-target-admin"
SERVER_VERSION = "1.0.0"

# The exact resource the cred-reach witness points at. The harness computes the
# witness resource_id from ("MCPResource", server_id, GATED_RESOURCE_URI), so
# this string is a cross-component contract — do not change it without also
# updating lib/gen-witness.sh.
GATED_RESOURCE_URI = "file:///data/support-cases/case-001.json"

# A second, anonymously-listable resource whose URI trips the critical
# sensitivity rule (`/secrets` keyword) so `scan` exercises resource
# sensitivity classification. It is NOT gated.
PUBLIC_SENSITIVE_URI = "file:///secrets/support-api-tokens.json"

# sha256hex of the accepted bearer token. Empty => the gate denies every
# resources/read of the gated URI (fine for the unauth control probe; the
# harness always sets this so the authed probe can pass).
GATED_RESOURCE_TOKEN_HASH = os.environ.get("GATED_RESOURCE_TOKEN_HASH", "").strip().lower()


# --------------------------------------------------------------------------- #
# Shared mutable state: one dict read by BOTH the MCP list_tools handler and
# the bare JSON-RPC /admin routes, so a PUT is visible on the next scan.
# --------------------------------------------------------------------------- #
def _default_tools() -> dict[str, dict[str, Any]]:
    return {
        # Poison target for `mcppoison --target-id support_lookup`.
        "support_lookup": {
            "description": (
                "Look up a customer support case by its case ID and return the "
                "account notes, contact details, and billing history."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Support case identifier."}
                },
                "required": ["case_id"],
            },
        },
        # Untrusted-web source (tool name matches the source-untrusted-web rule).
        "web_fetch": {
            "description": (
                "Fetch the readable contents of a web page by URL so the "
                "assistant can summarize third-party documentation."
            ),
            "input_schema": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
        # Untrusted-email source (name matches the source-untrusted-email rule).
        "read_inbox": {
            "description": "Read the latest messages from the shared support inbox.",
            "input_schema": {
                "type": "object",
                "properties": {"folder": {"type": "string"}},
            },
        },
        # Untrusted-fileshare source ("network share" matches the rule).
        "fileshare_search": {
            "description": (
                "Search the team network share for documents and download "
                "matching files."
            ),
            "input_schema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
        # Cross-references support_lookup -> collector flags has_cross_references.
        "escalate_case": {
            "description": (
                "Escalate a case previously opened via support_lookup to a "
                "human agent who is on call."
            ),
            "input_schema": {
                "type": "object",
                "properties": {"case_id": {"type": "string"}},
                "required": ["case_id"],
            },
        },
        # Benign control tool.
        "kb_search": {
            "description": "Search the internal product knowledge base for troubleshooting articles.",
            "input_schema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    }


TOOLS: dict[str, dict[str, Any]] = _default_tools()

_RESOURCES: dict[str, dict[str, Any]] = {
    GATED_RESOURCE_URI: {
        "name": "support-case-001",
        "description": "Full support case record including customer PII (credential-gated).",
        "mime_type": "application/json",
        "content": json.dumps(
            {
                "case_id": "case-001",
                "account": "acme-corp",
                "summary": "Customer reports intermittent 500s on the billing API.",
                "contact": {"name": "Dana Ops", "email": "dana@acme.example"},
            }
        ),
    },
    PUBLIC_SENSITIVE_URI: {
        "name": "support-api-tokens",
        "description": "Support automation API token store.",
        "mime_type": "application/json",
        "content": json.dumps({"note": "token values redacted in the harness fixture"}),
    },
}

_RESOURCE_TEMPLATES = [
    {
        "uri_template": "file:///data/support-cases/{case_id}.json",
        "name": "support-case-by-id",
        "description": "A support case record addressed by case ID.",
        "mime_type": "application/json",
    }
]

_PROMPTS = [
    {
        "name": "triage_case",
        "description": "Draft a triage summary for a support case.",
        "arguments": [
            types.PromptArgument(name="case_id", description="Support case identifier.", required=True)
        ],
    },
    {
        "name": "escalation_email",
        "description": "Compose an escalation email to the on-call engineer.",
        "arguments": [
            types.PromptArgument(name="case_id", description="Support case identifier.", required=True),
            types.PromptArgument(name="severity", description="Escalation severity.", required=False),
        ],
    },
]


# --------------------------------------------------------------------------- #
# MCP low-level server + handlers.
# --------------------------------------------------------------------------- #
server: Server = Server(SERVER_NAME, version=SERVER_VERSION)


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name=name, description=spec["description"], inputSchema=spec["input_schema"])
        for name, spec in TOOLS.items()
    ]


@server.list_resources()
async def list_resources() -> list[types.Resource]:
    return [
        types.Resource(
            uri=uri,
            name=spec["name"],
            description=spec["description"],
            mimeType=spec["mime_type"],
        )
        for uri, spec in _RESOURCES.items()
    ]


@server.list_resource_templates()
async def list_resource_templates() -> list[types.ResourceTemplate]:
    return [
        types.ResourceTemplate(
            uriTemplate=tmpl["uri_template"],
            name=tmpl["name"],
            description=tmpl["description"],
            mimeType=tmpl["mime_type"],
        )
        for tmpl in _RESOURCE_TEMPLATES
    ]


@server.read_resource()
async def read_resource(uri: Any) -> str:
    # By the time a read of the gated URI reaches here, the ASGI gate has
    # already verified the bearer token (or short-circuited with 401).
    key = str(uri)
    spec = _RESOURCES.get(key)
    if spec is not None:
        return spec["content"]
    # Support template instances like file:///data/support-cases/case-042.json.
    if key.startswith("file:///data/support-cases/") and key.endswith(".json"):
        return json.dumps({"case_id": key.rsplit("/", 1)[-1][:-5], "account": "acme-corp"})
    raise ValueError(f"unknown resource: {key}")


@server.list_prompts()
async def list_prompts() -> list[types.Prompt]:
    return [
        types.Prompt(name=p["name"], description=p["description"], arguments=p["arguments"])
        for p in _PROMPTS
    ]


@server.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
    case_id = (arguments or {}).get("case_id", "<case_id>")
    return types.GetPromptResult(
        description=f"Prompt {name}",
        messages=[
            types.PromptMessage(
                role="user",
                content=types.TextContent(type="text", text=f"Summarize support case {case_id}."),
            )
        ],
    )


session_manager = StreamableHTTPSessionManager(app=server, event_store=None)


# --------------------------------------------------------------------------- #
# Credential gate: an ASGI wrapper around the MCP session manager. It peeks the
# JSON-RPC body and returns a real HTTP 401 for an unauthenticated
# resources/read of the gated URI. Everything else is forwarded untouched.
# --------------------------------------------------------------------------- #
def _bearer_token(scope: dict) -> str | None:
    for raw_name, raw_value in scope.get("headers", []):
        if raw_name == b"authorization":
            value = raw_value.decode("latin-1").strip()
            parts = value.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                return parts[1]
            return None
    return None


def _token_authorized(scope: dict) -> bool:
    if not GATED_RESOURCE_TOKEN_HASH:
        return False
    token = _bearer_token(scope)
    if not token:
        return False
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, GATED_RESOURCE_TOKEN_HASH)


def _requests_gated_read(body: bytes) -> bool:
    """True if the JSON-RPC body is a resources/read of the gated URI."""
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return False
    messages = payload if isinstance(payload, list) else [payload]
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("method") != "resources/read":
            continue
        params = message.get("params")
        if isinstance(params, dict) and params.get("uri") == GATED_RESOURCE_URI:
            return True
    return False


async def _send_unauthorized(send) -> None:
    body = json.dumps(
        {"error": "unauthorized", "detail": "credential required for resources/read of gated resource"}
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", b'Bearer realm="mcp-target-admin"'),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _replay_receive(body: bytes, original_receive):
    """Replay the already-consumed request body, then delegate.

    The buffered body is delivered on the first call. Subsequent calls fall
    through to the real ASGI receive so the streamable-HTTP session manager can
    still observe a genuine `http.disconnect` while it streams its SSE response.
    Returning a synthetic disconnect here would abort that stream mid-flight
    ("ASGI callable returned without completing response").
    """
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await original_receive()

    return receive


async def gated_mcp_app(scope, receive, send) -> None:
    if scope["type"] != "http" or scope.get("method") != "POST":
        await session_manager.handle_request(scope, receive, send)
        return

    body = b""
    while True:
        message = await receive()
        if message["type"] == "http.request":
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        elif message["type"] == "http.disconnect":
            break

    if _requests_gated_read(body) and not _token_authorized(scope):
        await _send_unauthorized(send)
        return

    await session_manager.handle_request(scope, _replay_receive(body, receive), send)


# --------------------------------------------------------------------------- #
# Bare JSON-RPC admin surface (no MCP session). Shares the TOOLS dict.
# --------------------------------------------------------------------------- #
async def admin_tools_list(request: Request) -> JSONResponse:
    request_id: Any = 1
    try:
        payload = await request.json()
        if isinstance(payload, dict) and "id" in payload:
            request_id = payload["id"]
    except (ValueError, TypeError):
        pass
    tools = [
        {"name": name, "description": spec["description"], "inputSchema": spec["input_schema"]}
        for name, spec in TOOLS.items()
    ]
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})


async def admin_update_tool(request: Request) -> JSONResponse:
    name = request.path_params["name"]
    if name not in TOOLS:
        return JSONResponse({"error": f"unknown tool: {name}"}, status_code=404)
    try:
        body = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"error": "invalid JSON body"}, status_code=400)
    description = body.get("description") if isinstance(body, dict) else None
    if not isinstance(description, str):
        return JSONResponse({"error": "body must be {\"description\": string}"}, status_code=400)
    TOOLS[name]["description"] = description
    return JSONResponse({"ok": True, "name": name, "description": description})


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "server": SERVER_NAME})


# The admin + health routes live on a small Starlette app; its lifespan runs the
# streamable-HTTP session manager's task group.
_admin_app = Starlette(
    routes=[
        Route("/healthz", healthz, methods=["GET"]),
        Route("/admin/tools-list", admin_tools_list, methods=["POST", "GET"]),
        Route("/admin/tools/{name}", admin_update_tool, methods=["PUT"]),
    ],
    lifespan=lambda _app: session_manager.run(),
)


async def app(scope, receive, send) -> None:
    """Top-level ASGI dispatcher.

    The MCP endpoint is answered in place at both `/mcp` and `/mcp/` (no Starlette
    Mount, hence no 307 slash-redirect): the collector's Go MCP client and the
    cred-reach prober POST to the exact endpoint `http://<host>:8080/mcp`, and a
    redirect hop risks dropping the request body or the origin-scoped
    Authorization header. Everything else (admin surface, health, lifespan) is
    handled by the Starlette app, whose lifespan starts the session manager.
    """
    if scope["type"] == "http" and scope.get("path") in ("/mcp", "/mcp/"):
        await gated_mcp_app(scope, receive, send)
        return
    await _admin_app(scope, receive, send)
