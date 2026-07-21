"""Real A2A auth-observation lanes backed by a2aproject/a2a-python 1.1.0.

The four public Agent Cards and JSON-RPC handlers exercise the release contract:

* /           — v1.0 anonymous GetTask returns the SDK's exact TaskNotFound.
* /legacy     — official v0.3 compatibility card/dispatcher does the same.
* /protected  — the public card declares an active API-key requirement while
                the protocol handler rejects an anonymous request with 401.
* /ambiguous  — the card advertises v1.9, producing the SDK's version error;
                this must remain unknown rather than becoming no-auth evidence.

Every handler uses DefaultRequestHandler and a counted InMemoryTaskStore. The
read-only /probe-state endpoint lets the harness prove that collection issued
only GetTask/tasks/get, forwarded no operator credential, never invoked an
AgentExecutor, and never saved or deleted a task.
"""

import os
import uuid

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from a2a.compat.v0_3.conversions import to_compat_agent_card
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.request_handlers.response_helpers import build_error_response
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
    SecurityRequirement,
    SecurityScheme,
    StringList,
)
from a2a.utils.constants import DEFAULT_RPC_URL, TransportProtocol
from a2a.utils.errors import VersionNotSupportedError

PORT = int(os.environ.get("PORT", "9000"))
BASE_URL = os.environ.get("A2A_BASE_URL", f"http://a2a-dynamic:{PORT}").rstrip("/")
PROTECTED_API_KEY = os.environ.get(
    "A2A_PROTECTED_API_KEY", "agenthound-a2a-api-key-not-production"
)


class LaneState:
    def __init__(self) -> None:
        self.protocol_requests = 0
        self.get_task_requests = 0
        self.non_get_task_requests = 0
        self.credential_header_requests = 0
        self.executor_calls = 0
        self.task_store_saves = 0
        self.task_store_deletes = 0

    def snapshot(self) -> dict[str, int]:
        return {
            "protocol_requests": self.protocol_requests,
            "get_task_requests": self.get_task_requests,
            "non_get_task_requests": self.non_get_task_requests,
            "credential_header_requests": self.credential_header_requests,
            "executor_calls": self.executor_calls,
            "task_store_saves": self.task_store_saves,
            "task_store_deletes": self.task_store_deletes,
        }


class CountingTaskStore(InMemoryTaskStore):
    def __init__(self, state: LaneState) -> None:
        super().__init__()
        self.state = state

    async def save(self, task, context) -> None:
        self.state.task_store_saves += 1
        await super().save(task, context)

    async def delete(self, task_id, context) -> None:
        self.state.task_store_deletes += 1
        await super().delete(task_id, context)


class CountingAgentExecutor(AgentExecutor):
    def __init__(self, state: LaneState) -> None:
        self.state = state

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.state.executor_calls += 1
        await event_queue.enqueue_event(
            Message(
                message_id=str(uuid.uuid4()),
                role=Role.ROLE_AGENT,
                parts=[Part(text="Request reached the fixture executor.")],
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.state.executor_calls += 1
        raise NotImplementedError("cancellation is not supported by this demo agent")


def build_agent_card(
    *,
    name: str,
    description: str,
    endpoint: str,
    protocol_versions: list[str],
    skill_id: str,
    skill_name: str,
    publish_api_key_scheme: bool = False,
    require_api_key: bool = False,
) -> AgentCard:
    security_schemes = {}
    security_requirements = []
    if publish_api_key_scheme:
        security_schemes = {
            "api_key": SecurityScheme(
                api_key_security_scheme=APIKeySecurityScheme(
                    location="header",
                    name="X-API-Key",
                    description="Static API key.",
                )
            )
        }
    if require_api_key:
        security_requirements = [
            SecurityRequirement(schemes={"api_key": StringList(list=[])})
        ]

    return AgentCard(
        name=name,
        description=description,
        version="1.0.0",
        provider=AgentProvider(
            organization="AgentHoundA2ATest", url="https://example.invalid"
        ),
        supported_interfaces=[
            AgentInterface(
                url=endpoint,
                protocol_binding=TransportProtocol.JSONRPC.value,
                protocol_version=protocol_version,
            )
            for protocol_version in protocol_versions
        ],
        capabilities=AgentCapabilities(streaming=True, push_notifications=False),
        security_schemes=security_schemes,
        security_requirements=security_requirements,
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        skills=[
            AgentSkill(
                id=skill_id,
                name=skill_name,
                description=f"Read-only fixture skill for {name}.",
                tags=["agenthound", "release-test"],
                input_modes=["application/json"],
                output_modes=["application/json"],
            )
        ],
    )


def instrument_jsonrpc_route(
    handler: DefaultRequestHandler,
    rpc_path: str,
    state: LaneState,
    *,
    enable_v0_3_compat: bool,
    require_api_key: bool = False,
    force_version_error: bool = False,
) -> Route:
    sdk_route = create_jsonrpc_routes(
        handler,
        rpc_path,
        enable_v0_3_compat=enable_v0_3_compat,
    )[0]

    async def observed_endpoint(request: Request):
        state.protocol_requests += 1
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        method = payload.get("method") if isinstance(payload, dict) else None
        if method in ("GetTask", "tasks/get"):
            state.get_task_requests += 1
        else:
            state.non_get_task_requests += 1
        if any(
            request.headers.get(header)
            for header in ("authorization", "cookie", "x-api-key")
        ):
            state.credential_header_requests += 1

        if require_api_key and request.headers.get("x-api-key") != PROTECTED_API_KEY:
            return JSONResponse(
                {"error": "authentication required"},
                status_code=401,
                headers={"WWW-Authenticate": "ApiKey"},
            )
        if force_version_error:
            request_id = payload.get("id") if isinstance(payload, dict) else None
            return JSONResponse(
                build_error_response(request_id, VersionNotSupportedError())
            )
        return await sdk_route.endpoint(request)

    return Route(rpc_path, observed_endpoint, methods=["POST"])


def build_app() -> Starlette:
    lanes = {
        "v1": LaneState(),
        "v0_3": LaneState(),
        "protected": LaneState(),
        "ambiguous": LaneState(),
    }
    cards = {
        "v1": build_agent_card(
            name="ClaimsTriageAgent",
            description=(
                "Insurance claims triage agent served by the official SDK; "
                "routes payroll tasks to PayrollAgent."
            ),
            endpoint=f"{BASE_URL}/",
            protocol_versions=["1.0", "0.3"],
            skill_id="triage-claim",
            skill_name="TriageClaim",
            publish_api_key_scheme=True,
        ),
        "v0_3": build_agent_card(
            name="LegacySDKAgent",
            description="Official SDK v0.3 compatibility endpoint.",
            endpoint=f"{BASE_URL}/legacy",
            protocol_versions=["0.3"],
            skill_id="legacy-sdk-lookup",
            skill_name="LegacySDKLookup",
        ),
        "protected": build_agent_card(
            name="ProtectedPaymentsAgent",
            description="API-key protected official SDK endpoint.",
            endpoint=f"{BASE_URL}/protected",
            protocol_versions=["1.0"],
            skill_id="protected-payment-lookup",
            skill_name="ProtectedPaymentLookup",
            publish_api_key_scheme=True,
            require_api_key=True,
        ),
        "ambiguous": build_agent_card(
            name="VersionAmbiguousAgent",
            description="Official SDK unsupported-version control endpoint.",
            endpoint=f"{BASE_URL}/ambiguous",
            protocol_versions=["1.9"],
            skill_id="ambiguous-control",
            skill_name="AmbiguousControl",
        ),
    }

    handlers = {
        name: DefaultRequestHandler(
            agent_executor=CountingAgentExecutor(lanes[name]),
            task_store=CountingTaskStore(lanes[name]),
            agent_card=card,
        )
        for name, card in cards.items()
    }

    async def legacy_card(_request: Request):
        compat = to_compat_agent_card(cards["v0_3"])
        return JSONResponse(compat.model_dump(mode="json", exclude_none=True))

    async def health(_request: Request):
        return JSONResponse({"status": "ok"})

    async def probe_state(_request: Request):
        return JSONResponse({name: state.snapshot() for name, state in lanes.items()})

    routes = []
    routes.extend(create_agent_card_routes(cards["v1"]))
    routes.extend(
        create_agent_card_routes(
            cards["protected"], card_url="/protected/.well-known/agent-card.json"
        )
    )
    routes.extend(
        create_agent_card_routes(
            cards["ambiguous"], card_url="/ambiguous/.well-known/agent-card.json"
        )
    )
    routes.append(
        Route(
            "/legacy/.well-known/agent.json",
            legacy_card,
            methods=["GET"],
        )
    )
    routes.append(
        instrument_jsonrpc_route(
            handlers["v1"],
            DEFAULT_RPC_URL,
            lanes["v1"],
            enable_v0_3_compat=True,
        )
    )
    routes.append(
        instrument_jsonrpc_route(
            handlers["v0_3"],
            "/legacy",
            lanes["v0_3"],
            enable_v0_3_compat=True,
        )
    )
    routes.append(
        instrument_jsonrpc_route(
            handlers["protected"],
            "/protected",
            lanes["protected"],
            enable_v0_3_compat=False,
            require_api_key=True,
        )
    )
    routes.append(
        instrument_jsonrpc_route(
            handlers["ambiguous"],
            "/ambiguous",
            lanes["ambiguous"],
            enable_v0_3_compat=False,
            force_version_error=True,
        )
    )
    routes.extend(
        [
            Route("/healthz", health, methods=["GET"]),
            Route("/probe-state", probe_state, methods=["GET"]),
        ]
    )
    return Starlette(routes=routes)


app = build_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
