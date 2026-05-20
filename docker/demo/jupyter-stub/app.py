"""Jupyter Server fingerprint stub — answers /api/status with the four
canonical Jupyter status fields."""
from datetime import datetime, timezone

from fastapi import FastAPI

app = FastAPI()
STARTED = datetime.now(tz=timezone.utc).isoformat()


@app.get("/api/status")
def status():
    return {
        "started": STARTED,
        "last_activity": datetime.now(tz=timezone.utc).isoformat(),
        "connections": 1,
        "kernels": 1,
    }
