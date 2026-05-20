"""A2A agent discovery stub — serves a valid agent-card at the well-known
path so the v0.3 `agenthound discover` verb finds it via protoscan."""
from fastapi import FastAPI

app = FastAPI()


@app.get("/.well-known/agent-card.json")
def agent_card():
    return {
        "name": "demo-a2a-agent",
        "description": "Demo A2A agent for the v0.3 lab",
        "url": "http://172.30.0.80:8080/api",
        "version": "0.3.0-demo",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "skills": [
            {
                "id": "summarize",
                "name": "Summarize",
                "description": "Summarize a document or conversation.",
            }
        ],
    }
