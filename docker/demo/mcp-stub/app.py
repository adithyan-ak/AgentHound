"""MCP server demo stub.

Two surfaces:

  1. JSON-RPC `initialize` and `tools/list` (POST /  and POST /mcp)
     so `agenthound discover` finds the server and `agenthound poison`
     can read the current tool description.

  2. PUT /admin/tools/{tool_id}  with body {"description": "..."}
     so `agenthound poison --type mcp.tool.description` can rewrite
     the description, and `agenthound revert` can put it back.

The "support_lookup" tool ships with a benign description; the demo
arc poisons it to redirect the agent's behavior, runs an agent
invocation against the poisoned description, then reverts.
"""
import threading

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

_LOCK = threading.Lock()
_TOOLS = {
    "support_lookup": {
        "name": "support_lookup",
        "description": "Look up a customer's open support tickets by email.",
        "inputSchema": {
            "type": "object",
            "properties": {"email": {"type": "string"}},
            "required": ["email"],
        },
    }
}


def _jsonrpc_response(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


@app.post("/")
@app.post("/mcp")
async def jsonrpc(req: Request):
    body = await req.json()
    method = body.get("method")
    req_id = body.get("id", 1)
    if method == "initialize":
        return _jsonrpc_response(
            req_id,
            {
                "protocolVersion": body.get("params", {}).get(
                    "protocolVersion", "2025-11-25"
                ),
                "serverInfo": {
                    "name": "demo-mcp-server",
                    "version": "0.4.0-demo",
                },
                "capabilities": {"tools": {"listChanged": False}},
            },
        )
    if method == "tools/list":
        with _LOCK:
            tools = list(_TOOLS.values())
        return _jsonrpc_response(req_id, {"tools": tools})
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": "Method not found"},
    }


@app.put("/admin/tools/{tool_id}", status_code=204)
async def update_tool(tool_id: str, req: Request):
    body = await req.json()
    new_desc = body.get("description")
    if not isinstance(new_desc, str):
        raise HTTPException(status_code=400, detail="description must be a string")
    with _LOCK:
        if tool_id not in _TOOLS:
            raise HTTPException(status_code=404, detail="tool not found")
        _TOOLS[tool_id]["description"] = new_desc
    return None
