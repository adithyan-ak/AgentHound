"""Open WebUI fingerprint stub — answers /api/version with the canonical
{"version": "X.Y.Z"} JSON and /api/config with the configured Ollama
backend so the fingerprinter emits the EXPOSES edge to the upstream
Ollama node."""
import os

from fastapi import FastAPI

app = FastAPI()
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://ollama:11434")


@app.get("/api/version")
def version():
    return {"version": "0.6.5"}


@app.get("/api/config")
def config():
    return {
        "name": "Open WebUI (demo)",
        "version": "0.6.5",
        "ollama": {"base_url": OLLAMA_BASE_URL},
        "features": {"auth": False},
    }
