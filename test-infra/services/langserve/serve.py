from typing import Any

from fastapi import FastAPI
from langchain_core.runnables import RunnableLambda
from langserve import add_routes


def echo(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the input unchanged without calling an external model."""
    return payload


app = FastAPI(
    title="AgentHound LangServe Fixture",
    version="1.0.0",
    description="Deterministic local LangServe API for collector QA.",
)

add_routes(app, RunnableLambda(echo), path="/echo")
