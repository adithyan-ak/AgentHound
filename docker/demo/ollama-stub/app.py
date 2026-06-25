# pyright: reportMissingImports=false
"""Deterministic Ollama API stub for the AgentHound demo lab.

The real Ollama image requires a live model pull before the looter can
produce useful output. This stub serves the tiny API surface AgentHound
uses so the DEFCON demo is fast, offline, and repeatable.
"""
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

MODELS = {
    "tinyllama:latest": {
        "model": "tinyllama:latest",
        "name": "tinyllama:latest",
        "digest": "sha256:demo-tinyllama",
        "size": 637_000_000,
        "modified_at": "2026-06-25T00:00:00Z",
        "modelfile": "FROM tinyllama\n",
        "template": "{{ .Prompt }}",
        "system": "",
        "details": {
            "family": "llama",
            "parameter_size": "1.1B",
            "quantization_level": "Q4_0",
        },
    },
    "support-agent-v3:latest": {
        "model": "support-agent-v3:latest",
        "name": "support-agent-v3:latest",
        "digest": "sha256:demo-support-agent-v3",
        "size": 637_000_000,
        "modified_at": "2026-06-25T00:00:00Z",
        "modelfile": (
            "FROM tinyllama\n"
            'SYSTEM """You are SupportBot for Acme Corp. Internal triage assistant only."""\n'
        ),
        "template": "{{ .System }}\n{{ .Prompt }}",
        "system": "You are SupportBot for Acme Corp. Internal triage assistant only.",
        "details": {
            "family": "llama",
            "parameter_size": "1.1B",
            "quantization_level": "Q4_0",
        },
    },
}


@app.get("/api/version")
def version():
    return {"version": "0.6.8"}


@app.get("/api/tags")
def tags():
    return {
        "models": [
            {
                "model": model["model"],
                "name": model["name"],
                "digest": model["digest"],
                "size": model["size"],
                "modified_at": model["modified_at"],
            }
            for model in MODELS.values()
        ]
    }


@app.post("/api/show")
async def show(req: Request):
    body = await req.json()
    name = body.get("name")
    if not isinstance(name, str) or not name:
        raise HTTPException(status_code=400, detail="name is required")
    model = MODELS.get(name) or MODELS.get(f"{name}:latest")
    if model is None:
        raise HTTPException(status_code=404, detail="model not found")
    return {
        "modelfile": model["modelfile"],
        "template": model["template"],
        "system": model["system"],
        "details": model["details"],
    }
