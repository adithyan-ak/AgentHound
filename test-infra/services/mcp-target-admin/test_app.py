"""Focused local tests for the authored MCP target.

Runs a real uvicorn server and exercises the exact wire contracts the collector
depends on:

  * anonymous MCP `initialize` + enumeration (`scan --mcp` / `discover`),
  * the credential-gated `resources/read` returning a transport-level HTTP 401
    unauthenticated and HTTP 200 with the hash-matched bearer (cred-reach
    control vs. authed probe),
  * the bare JSON-RPC `/admin/tools-list` and `PUT /admin/tools/{name}` that
    `mcppoison` drives, and that a PUT is reflected on the next MCP `tools/list`.

Run with either:  python test_app.py      (stdlib unittest)
              or:  python -m pytest test_app.py

Requires the runtime deps in requirements.txt (mcp, starlette, uvicorn, httpx).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import threading
import time
import unittest

# The server reads GATED_RESOURCE_TOKEN_HASH at import time, so set it first.
_SECRET = "sk-fake-test-secret"
os.environ["GATED_RESOURCE_TOKEN_HASH"] = hashlib.sha256(_SECRET.encode()).hexdigest()

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamablehttp_client  # noqa: E402

import app as appmod  # noqa: E402

_ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
_INIT = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}

_server: uvicorn.Server | None = None
_base = ""
_mcp = ""


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def setUpModule() -> None:
    global _server, _base, _mcp
    # A fresh tools dict per run keeps the PUT-mutation test independent.
    appmod.TOOLS.clear()
    appmod.TOOLS.update(appmod._default_tools())
    port = _free_port()
    _base = f"http://127.0.0.1:{port}"
    _mcp = f"{_base}/mcp"
    config = uvicorn.Config(appmod.app, host="127.0.0.1", port=port, log_level="warning")
    _server = uvicorn.Server(config)
    threading.Thread(target=_server.run, daemon=True).start()
    for _ in range(200):
        if _server.started:
            break
        time.sleep(0.05)
    time.sleep(0.3)


def tearDownModule() -> None:
    if _server is not None:
        _server.should_exit = True
    time.sleep(0.3)


async def _enumerate(headers=None):
    async with streamablehttp_client(_mcp, headers=headers, timeout=8) as (reader, writer, _):
        async with ClientSession(reader, writer) as session:
            init = await session.initialize()
            tools = await session.list_tools()
            resources = await session.list_resources()
            templates = await session.list_resource_templates()
            prompts = await session.list_prompts()
            return init, tools, resources, templates, prompts


def _run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=25))


class MCPEnumerationTest(unittest.TestCase):
    def test_anonymous_enumeration_populates_collector_surface(self) -> None:
        init, tools, resources, templates, prompts = _run(_enumerate())
        self.assertEqual(init.serverInfo.name, "mcp-target-admin")
        self.assertIsNotNone(init.capabilities.tools)
        self.assertIsNotNone(init.capabilities.resources)
        self.assertIsNotNone(init.capabilities.prompts)
        self.assertGreaterEqual(len(tools.tools), 5)
        self.assertIn("support_lookup", {t.name for t in tools.tools})
        self.assertGreaterEqual(len(resources.resources), 2)
        self.assertIn(appmod.GATED_RESOURCE_URI, {str(r.uri) for r in resources.resources})
        self.assertGreaterEqual(len(templates.resourceTemplates), 1)
        self.assertGreaterEqual(len(prompts.prompts), 1)


class CredentialGateTest(unittest.TestCase):
    def _handshake(self, client: httpx.Client) -> dict:
        resp = client.post(_mcp, headers=_ACCEPT, json=_INIT)
        self.assertEqual(resp.status_code, 200)
        sid = resp.headers.get("mcp-session-id")
        headers = dict(_ACCEPT)
        if sid:
            headers["mcp-session-id"] = sid
        client.post(_mcp, headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        return headers

    def _read(self, client, headers, req_id):
        return client.post(
            _mcp,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "resources/read",
                "params": {"uri": appmod.GATED_RESOURCE_URI},
            },
        )

    def test_gate_denies_unauth_allows_hash_matched_bearer(self) -> None:
        with httpx.Client(follow_redirects=True) as client:
            headers = self._handshake(client)

            anon = self._read(client, headers, 1)
            self.assertEqual(anon.status_code, 401, "unauth control probe must observe HTTP 401")

            wrong = self._read(client, {**headers, "Authorization": "Bearer nope"}, 2)
            self.assertEqual(wrong.status_code, 401, "non-matching bearer must be denied")

            authed = self._read(client, {**headers, "Authorization": f"Bearer {_SECRET}"}, 3)
            self.assertEqual(authed.status_code, 200, "hash-matched bearer must be allowed")
            self.assertIn("case-001", authed.text)

    def test_enumeration_stays_anonymous(self) -> None:
        with httpx.Client(follow_redirects=True) as client:
            headers = self._handshake(client)
            for method in ("resources/list", "resources/templates/list", "tools/list", "prompts/list"):
                resp = client.post(_mcp, headers=headers, json={"jsonrpc": "2.0", "id": 5, "method": method})
                self.assertEqual(resp.status_code, 200, f"{method} must stay anonymous")


class AdminSurfaceTest(unittest.TestCase):
    def test_bare_jsonrpc_list_put_and_scan_reflect_same_state(self) -> None:
        with httpx.Client() as client:
            listed = client.post(
                f"{_base}/admin/tools-list", json={"jsonrpc": "2.0", "id": 42, "method": "tools/list"}
            )
            self.assertEqual(listed.status_code, 200)
            body = listed.json()
            self.assertEqual(body["id"], 42)
            names = {t["name"] for t in body["result"]["tools"]}
            self.assertIn("support_lookup", names)

            put = client.put(
                f"{_base}/admin/tools/support_lookup", json={"description": "TAMPERED-BY-POISON"}
            )
            self.assertEqual(put.status_code, 200)

            after = client.post(
                f"{_base}/admin/tools-list", json={"jsonrpc": "2.0", "id": 43, "method": "tools/list"}
            )
            desc = next(t["description"] for t in after.json()["result"]["tools"] if t["name"] == "support_lookup")
            self.assertEqual(desc, "TAMPERED-BY-POISON")

            missing = client.put(f"{_base}/admin/tools/does_not_exist", json={"description": "x"})
            self.assertEqual(missing.status_code, 404)

        # The MCP scan path reads the same in-memory dict, so it sees the PUT.
        _, tools, _, _, _ = _run(_enumerate())
        scanned = next(t.description for t in tools.tools if t.name == "support_lookup")
        self.assertEqual(scanned, "TAMPERED-BY-POISON")


if __name__ == "__main__":
    unittest.main(verbosity=2)
