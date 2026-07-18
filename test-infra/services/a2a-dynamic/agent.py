"""Real A2A agent served by the a2aproject/a2a-python SDK (a2a-sdk 1.1.0).

Exposes the standard A2A surface on port 9000:
  - GET  /.well-known/agent-card.json  (the public AgentCard)
  - POST /                             (JSON-RPC agent endpoint, v1.0 + v0.3 compat)
  - GET  /healthz                      (liveness)

The card is built from the SDK's own proto AgentCard model and serialized by the
SDK's `agent_card_to_dict`, so it emits the genuine A2A 1.0 structure
(`supportedInterfaces`) merged with v0.3 backward-compatibility fields. AgentHound
classifies a card carrying `supportedInterfaces` as v1.0 and drives its
`parseV10` path. Two interfaces (protocolVersion 1.0 and 0.3) exercise both the
current and legacy protocol advertisements the SDK supports in compatibility mode.
"""

import os
import uuid

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    APIKeySecurityScheme,
    Message,
    Part,
    Role,
    SecurityScheme,
)
from a2a.utils.constants import DEFAULT_RPC_URL, TransportProtocol

PORT = int(os.environ.get("PORT", "9000"))
BASE_URL = os.environ.get("A2A_BASE_URL", f"http://a2a-dynamic:{PORT}/")


def build_agent_card() -> AgentCard:
    return AgentCard(
        name="ClaimsTriageAgent",
        description=(
            "Insurance claims triage agent served by the a2a-python SDK; "
            "routes payroll tasks to PayrollAgent."
        ),
        version="1.0.0",
        provider=AgentProvider(
            organization="ContosoInsurance", url="https://contoso.example"
        ),
        supported_interfaces=[
            AgentInterface(
                url=BASE_URL,
                protocol_binding=TransportProtocol.JSONRPC.value,
                protocol_version="1.0",
            ),
            AgentInterface(
                url=BASE_URL,
                protocol_binding=TransportProtocol.JSONRPC.value,
                protocol_version="0.3",
            ),
        ],
        capabilities=AgentCapabilities(streaming=True, push_notifications=False),
        security_schemes={
            "api_key": SecurityScheme(
                api_key_security_scheme=APIKeySecurityScheme(
                    location="header",
                    name="X-API-Key",
                    description="Static API key.",
                )
            )
        },
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        skills=[
            AgentSkill(
                id="triage-claim",
                name="TriageClaim",
                description="Classify and route an incoming insurance claim.",
                tags=["insurance", "triage"],
                input_modes=["application/json"],
                output_modes=["application/json"],
            )
        ],
    )


class TriageAgentExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        await event_queue.enqueue_event(
            Message(
                message_id=str(uuid.uuid4()),
                role=Role.ROLE_AGENT,
                parts=[Part(text="Claim received and queued for triage.")],
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("cancellation is not supported by this demo agent")


def build_app() -> Starlette:
    card = build_agent_card()
    handler = DefaultRequestHandler(
        agent_executor=TriageAgentExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )

    async def health(_request):
        return JSONResponse({"status": "ok"})

    routes = []
    routes.extend(create_agent_card_routes(card))
    routes.extend(
        create_jsonrpc_routes(handler, DEFAULT_RPC_URL, enable_v0_3_compat=True)
    )
    routes.append(Route("/healthz", health, methods=["GET"]))
    return Starlette(routes=routes)


app = build_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
